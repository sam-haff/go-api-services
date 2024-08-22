#!/bin/bash

kubectl create configmap auth-server-env --from-env-file="../go-auth-server/k8s_dev.env"
kubectl create configmap foreign-api-env --from-env-file="../go-foreign-api/k8s_dev.env"
kubectl create configmap client-server-env --from-env-file="../go-api-server/k8s_dev.env"