# Makefile for Kubernetes Container Runtime Security Lab
# Targets: setup, deploy, test, scan, clean

SHELL := /bin/bash
CLUSTER_NAME := runtime-security-lab

.PHONY: help cluster deploy install-falco install-tetragon policies test scan clean

help:
	@echo "Available commands:"
	@echo "  make cluster           - Create KinD cluster with eBPF and debugfs mounts"
	@echo "  make deploy            - Apply namespaces and test workloads (dev, staging, prod)"
	@echo "  make install-falco     - Install Falco with custom eBPF rules via Helm"
	@echo "  make install-tetragon  - Install Cilium Tetragon with kernel sensors via Helm"
	@echo "  make policies          - Apply production Tetragon TracingPolicies"
	@echo "  make test              - Execute automated runtime security validation suite"
	@echo "  make scan              - Scan images (nginx:alpine) with Trivy and output JSON"
	@echo "  make clean             - Tear down local KinD cluster"

cluster:
	kind create cluster --config cluster/kind-config.yaml
	docker exec $(CLUSTER_NAME)-control-plane mount -t bpf bpf /sys/fs/bpf || true

deploy:
	kubectl apply -f namespaces/namespaces.yaml
	kubectl apply -f workloads/
	kubectl rollout status -n prod deployment/nginx-prod --timeout=90s
	kubectl rollout status -n staging deployment/nginx-staging --timeout=90s
	kubectl rollout status -n dev deployment/nginx-dev --timeout=90s

install-falco:
	helm repo add falcosecurity https://falcosecurity.github.io/charts
	helm repo update falcosecurity
	helm upgrade --install falco falcosecurity/falco \
		--namespace falco \
		--create-namespace \
		-f falco/values.yaml

install-tetragon:
	helm repo add cilium https://helm.cilium.io
	helm repo update cilium
	helm upgrade --install tetragon cilium/tetragon \
		--namespace kube-system \
		--set crds.installMethod=helm \
		-f tetragon/values.yaml
	kubectl rollout status -n kube-system ds/tetragon --timeout=90s
	kubectl wait --for=condition=Established --timeout=60s crd/tracingpolicies.cilium.io

policies:
	kubectl apply -f tetragon/policies/
	kubectl get tracingpolicy

test:
	chmod +x tests/run-runtime-security-tests.sh
	./tests/run-runtime-security-tests.sh

scan:
	chmod +x scripts/scan-images.sh
	./scripts/scan-images.sh

clean:
	kind delete cluster --name $(CLUSTER_NAME)
