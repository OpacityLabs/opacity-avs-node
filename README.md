# Opacity AVS Node

## Build the docker image

`sudo docker build . --tag opacity-node`

## Run the Docker container

`sudo docker run -it --device /dev/sgx_enclave -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket -v ./data:/workdir/data -p 7047:7047 opacity-node bash`

## Go to

https://<ip-address>:7047/info

You should see:
