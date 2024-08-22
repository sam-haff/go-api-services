#!/bin/bash

kubectl create secret generic auth-server-secret --from-env-file="../go-auth-server/k8s_secret_dev.env"