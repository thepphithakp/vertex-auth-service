#!/bin/bash
docker build -t vertex-auth-service:latest -f Dockerfile .
docker save vertex-auth-service:latest > vertex-auth-service.tar
echo '***REMOVED-SEE-VT-112***' | sudo -S bash -c 'k3s ctr images import vertex-auth-service.tar -n k8s.io && k3s ctr -n k8s.io images tag docker.io/library/vertex-auth-service:latest 192.168.1.82:32000/vertex-auth-service:latest && kubectl rollout restart deployment auth-service -n vertex'
