# Build stage
FROM gramineproject/gramine:v1.4 AS builder

ENV GRAMINE_SGXSSL_PATH=/usr/local/gramine-sgxssl

# Install basic tools and SGX packages in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget gnupg ca-certificates pkg-config libssl-dev openssl \
    openssh-client build-essential lld git protobuf-compiler \
    libsgx-dcap-default-qpl libsgx-dcap-quote-verify \
    libsgx-dcap-quote-verify-dev libsgx-urts sgx-aesm-service \
    libsgx-aesm-launch-plugin libsgx-aesm-epid-plugin \
    libsgx-aesm-quote-ex-plugin libsgx-dcap-ql \
    && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - \
    && echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" | tee /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    libsgx-dcap-default-qpl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opacity-avs-node
COPY . .
RUN mkdir bin

# Install Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Go and eigenlayer
RUN wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz \
    && tar -xvf go1.21.0.linux-amd64.tar.gz -C /usr/local \
    && rm go1.21.0.linux-amd64.tar.gz
ENV GOROOT=/usr/local/go
ENV HOME=/root
ENV GOPATH=$HOME/go
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH
RUN go install github.com/Layr-Labs/eigenlayer-cli/cmd/eigenlayer@v0.10.3 \
    && mv $GOPATH/bin/eigenlayer ./bin/

# Configure git and cargo
RUN git config --global url."https://github.com/".insteadOf git@github.com:
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# Generate temporary signing key
RUN mkdir -p /root/.config/gramine \
    && gramine-sgx-gen-private-key -f /root/.config/gramine/enclave-key.pem

# Build and sign
RUN cargo build --release \
    && make SGX=1

# Generate and sign manifest
RUN gramine-manifest \
    -Dlog_level=error \
    -Darch_libdir=/lib/x86_64-linux-gnu \
    -Dentrypoint=/opacity-avs-node/target/release/opacity-avs-node \
    opacity-avs-node.manifest.template > opacity-avs-node.manifest

# Don't move the files, leave them in target/release
RUN mkdir -p target/release

# Final stage
FROM gramineproject/gramine:v1.4 AS final
WORKDIR /opacity-avs-node

# Install runtime dependencies only
RUN echo "deb http://security.ubuntu.com/ubuntu focal-security main" > /etc/apt/sources.list.d/focal-security.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    openssl libssl1.1 libgcc1 make \
    libsgx-dcap-default-qpl libsgx-urts sgx-aesm-service \
    libsgx-aesm-launch-plugin libsgx-aesm-epid-plugin \
    libsgx-aesm-quote-ex-plugin libsgx-dcap-ql \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy files from builder
COPY --from=builder /opacity-avs-node/target/release/opacity-avs-node /opacity-avs-node/target/release/
COPY --from=builder /opacity-avs-node/target/release/register /opacity-avs-node/target/release/
COPY --from=builder /opacity-avs-node/opacity-avs-node.manifest* /opacity-avs-node/
COPY --from=builder /opacity-avs-node/Makefile /opacity-avs-node/
COPY start-node.sh /opacity-avs-node/
COPY register.sh /opacity-avs-node/

# Set permissions
RUN chmod +x /opacity-avs-node/start-node.sh /opacity-avs-node/register.sh /opacity-avs-node/Makefile

# Labels and configuration
LABEL org.opencontainers.image.source=https://github.com/OpacityLabs/opacity-avs-node
LABEL org.opencontainers.image.description="An implementation of the opacity avs node in Rust."
EXPOSE 7047 6047

CMD ["/opacity-avs-node/start-node.sh"]