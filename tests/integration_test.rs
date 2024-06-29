use async_tungstenite::{
    tokio::connect_async_with_tls_connector_and_config, tungstenite::protocol::WebSocketConfig,
};
use http_body_util::{BodyExt as _, Full};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Builder},
    rt::{TokioExecutor, TokioIo},
};
use notary_client::{NotarizationRequest, NotaryClient, NotaryConnection};
use rstest::rstest;
use rustls::{Certificate, RootCertStore};
use std::{string::String, time::Duration};
use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tlsn_prover::tls::{Prover, ProverConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;
use ws_stream_tungstenite::WsStream;

use opacity_avs_node::{
    read_pem_file, run_server, AuthorizationProperties, LoggingProperties, NotarizationProperties,
    NotarizationSessionRequest, NotarizationSessionResponse, NotaryServerProperties,
    NotarySigningKeyProperties, ServerProperties, TLSProperties,
};

const MAX_SENT_DATA: usize = 1 << 13;
const MAX_RECV_DATA: usize = 1 << 13;

const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_DNS: &str = "tlsnotaryserver.io";
const NOTARY_CA_CERT_PATH: &str = "../fixture/tls/rootCA.crt";
const NOTARY_CA_CERT_BYTES: &[u8] = include_bytes!("../fixture/tls/rootCA.crt");
const API_KEY: &str = "test_api_key_0";

fn get_server_config(port: u16, tls_enabled: bool, auth_enabled: bool) -> NotaryServerProperties {
    NotaryServerProperties {
        server: ServerProperties {
            name: NOTARY_DNS.to_string(),
            host: NOTARY_HOST.to_string(),
            port,
            html_info: "example html response".to_string(),
        },
        notarization: NotarizationProperties {
            max_transcript_size: 1 << 14,
        },
        tls: TLSProperties {
            enabled: tls_enabled,
            private_key_pem_path: Some("./fixture/notary/notary.key".to_string()),
            certificate_pem_path: Some("./fixture/tls/notary.crt".to_string()),
        },
        notary_key: NotarySigningKeyProperties {
            private_key_pem_path: "../fixture/notary/notary.key".to_string(),
            public_key_pem_path: "../fixture/notary/notary.pub".to_string(),
        },
        logging: LoggingProperties {
            level: "DEBUG".to_string(),
            filter: None,
        },
        authorization: AuthorizationProperties {
            enabled: auth_enabled,
            whitelist_csv_path: "../server/fixture/auth/whitelist.csv".to_string(),
        },
    }
}

async fn setup_config_and_server(
    sleep_ms: u64,
    port: u16,
    tls_enabled: bool,
    auth_enabled: bool,
) -> NotaryServerProperties {
    let notary_config = get_server_config(port, tls_enabled, auth_enabled);

    let _ = tracing_subscriber::fmt::try_init();

    let config = notary_config.clone();

    // Run the notary server
    tokio::spawn(async move {
        run_server(&config).await.unwrap();
    });

    // Sleep for a while to allow notary server to finish set up and start listening
    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

    notary_config
}

async fn tcp_prover(notary_config: NotaryServerProperties) -> (NotaryConnection, String) {
    let mut notary_client_builder = NotaryClient::builder();

    notary_client_builder
        .host(&notary_config.server.host)
        .port(notary_config.server.port)
        .enable_tls(false);

    if notary_config.authorization.enabled {
        notary_client_builder.api_key(API_KEY);
    }

    let notary_client = notary_client_builder.build().unwrap();

    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    let accepted_request = notary_client
        .request_notarization(notarization_request)
        .await
        .unwrap();

    (accepted_request.io, accepted_request.id)
}

async fn tls_prover(notary_config: NotaryServerProperties) -> (NotaryConnection, String) {
    let mut certificate_file_reader = read_pem_file(NOTARY_CA_CERT_PATH).await.unwrap();
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut certificate_file_reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let certificate = certificates.remove(0);

    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(&certificate).unwrap();

    let notary_client = NotaryClient::builder()
        .host(&notary_config.server.name)
        .port(notary_config.server.port)
        .root_cert_store(root_cert_store)
        .build()
        .unwrap();

    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    let accepted_request = notary_client
        .request_notarization(notarization_request)
        .await
        .unwrap();

    (accepted_request.io, accepted_request.id)
}

#[rstest]
// For `tls_without_auth` test to pass, one needs to add "<NOTARY_HOST> <NOTARY_DNS>" in /etc/hosts so that
// this test programme can resolve the self-named NOTARY_DNS to NOTARY_HOST IP successfully.
#[case::tls_without_auth(
    tls_prover(setup_config_and_server(100, 7047, true, false).await)
)]
#[case::tcp_with_auth(
    tcp_prover(setup_config_and_server(100, 7048, false, true).await)
)]
#[case::tcp_without_auth(
    tcp_prover(setup_config_and_server(100, 7049, false, false).await)
)]
#[awt]
#[tokio::test]
async fn test_tcp_prover<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    #[future]
    #[case]
    requested_notarization: (S, String),
) {
    let (notary_socket, session_id) = requested_notarization;

    let mut root_cert_store = tls_core::anchors::RootCertStore::empty();
    root_cert_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    // Prover config using the session_id returned from calling /session endpoint in notary client.
    let prover_config = ProverConfig::builder()
        .id(session_id)
        .server_dns(SERVER_DOMAIN)
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .root_cert_store(root_cert_store)
        .build()
        .unwrap();

    // Create a new Prover.
    let prover = Prover::new(prover_config)
        .setup(notary_socket.compat())
        .await
        .unwrap();

    // Connect to the Server.
    let (client_socket, server_socket) = tokio::io::duplex(1 << 16);
    let server_task = tokio::spawn(bind_test_server_hyper(server_socket.compat()));

    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover task to be run concurrently.
    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    tokio::spawn(connection);

    let request = Request::builder()
        .uri(format!("https://{}/echo", SERVER_DOMAIN))
        .method("POST")
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .body(Full::<Bytes>::new("echo".into()))
        .unwrap();

    debug!("Sending request to server: {:?}", request);

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    let payload = response.into_body().collect().await.unwrap().to_bytes();
    debug!(
        "Received response from server: {:?}",
        &String::from_utf8_lossy(&payload)
    );

    server_task.await.unwrap().unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_notarize();

    let sent_len = prover.sent_transcript().data().len();
    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();

    builder.commit_sent(&(0..sent_len)).unwrap();
    builder.commit_recv(&(0..recv_len)).unwrap();

    _ = prover.finalize().await.unwrap();

    debug!("Done notarization!");
}
