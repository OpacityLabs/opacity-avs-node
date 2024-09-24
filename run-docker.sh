OPERATOR_BLS_KEY_PASSWORD="" docker run -it --device /dev/sgx_enclave --device /dev/sgx_provision \
  		-v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
		--security-opt seccomp=seccomp.json \
  		--volume /home/ubuntu/.eigenlayer/operator_keys/opacity.bls.key.json:/opacity-avs-node/opacity.bls.key.json \
		-e OPERATOR_BLS_KEY_PASSWORD=$OPERATOR_BLS_KEY_PASSWORD\
		-p 7047:7047 \
  		opacitylabseulerlagrange/opacity-avs-node:latest bash