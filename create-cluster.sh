#!/bin/bash

# eksctl create cluster --name zktls-cluster-dev --fargate
# aws eks update-kubeconfig --name zktls-cluster-dev
# aws ecr create-repository --repository-name opacity-zktls-registry

aws ecr describe-repositories \
      --repository-names opacity-zktls-registry