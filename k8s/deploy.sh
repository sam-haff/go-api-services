#!/bin/bash

./apply-config-maps.sh
./apply-secrets.sh

kubectl apply -f go-api-server.yaml
kubectl apply -f go-auth-server.yaml
kubectl apply -f go-foreign-api.yaml