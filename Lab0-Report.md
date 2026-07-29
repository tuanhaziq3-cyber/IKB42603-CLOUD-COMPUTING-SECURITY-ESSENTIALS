# Lab 0 Report: Environment Setup & Verification

**Course:** IKB42603 Cloud Computing Security Essentials  
**Date:** 29/7/2026

**Environment:** Kali Linux VM (VirtualBox)  

---

## 1. Executive Summary
This report documents the installation, configuration, and verification of the local development and security testing environment for the IKB42603 lab series. All toolsets—including Docker, AWS CLI v2, kind, and kubectl—have been installed, verified, and configured to operate locally.

---

## 2. Core Tool Installations & Verifications

### 2.1 Docker & Storage Allocation
Docker is required to containerize applications and run local cloud simulators. The underlying virtual machine storage was expanded to accommodate container runtime images and local Kubernetes cluster nodes.

* **Version Verification Command:** `docker --version`
* **Test Container:** `docker run --rm hello-world`

> **<img width="1544" height="800" alt="image" src="https://github.com/user-attachments/assets/f68da26a-7b4f-4fc4-8d05-5b0506f91de1" />
**

---

### 2.2 AWS CLI v2 Setup
AWS CLI v2 was installed to interface with local AWS services without requiring an active AWS cloud account or remote credentials.

* **Version Verification Command:** `aws --version`

> **<img width="1286" height="134" alt="image" src="https://github.com/user-attachments/assets/49c5a1f8-193c-45e9-97e2-a63c510b0195" />
**

---

### 2.3 Kubernetes Tools (`kind` & `kubectl`)
`kind` (Kubernetes-in-Docker) and `kubectl` were deployed to build and manage local multi-node Kubernetes clusters.

* **kind Version:** `kind --version`
* **kubectl Client Version:** `kubectl version --client`

> **<img width="630" height="302" alt="image" src="https://github.com/user-attachments/assets/c108f944-f11b-43c5-9332-6765f92fd30e" />
**

---

### 2.4 Helper Tools
Verified availability of cryptographic and token utilities required for security analysis:

* **OpenSSL Version:** `openssl version`

> **<img width="1042" height="124" alt="image" src="https://github.com/user-attachments/assets/f22c807e-7d73-400e-a195-2aa73a3405ba" />
**

---

## 3. Local Environment Integration Tests

### 3.1 LocalStack Deployment & AWS Integration
LocalStack was deployed in a Docker container to simulate AWS services on port `4566`.

1. **LocalStack Container Status:** `docker ps`
2. **Health Check Endpoint:** `curl http://localhost:4566/_localstack/health`
3. **AWS CLI Endpoint Connectivity Test:**
   ```bash
   aws configure set aws_access_key_id test
   aws configure set aws_secret_access_key test
   aws configure set region us-east-1
   EP='--endpoint-url=http://localhost:4566'
   aws $EP sts get-caller-identity
<img width="846" height="286" alt="image" src="https://github.com/user-attachments/assets/5bbb8f8c-47db-42e0-a4a4-b57f08e7bd99" />

### 3.2 Kubernetes Cluster Deployment (`kind`)
A local Kubernetes cluster named `ccse` was instantiated and verified using `kind` and `kubectl`.

1. **Cluster Creation:** `kind create cluster --name ccse`
2. **Cluster Info & Node Status:**
   ```bash
   kubectl cluster-info --context kind-ccse
   kubectl get nodes
<img width="1762" height="1088" alt="image" src="https://github.com/user-attachments/assets/5d27a676-1620-4087-9e5e-8942489a6fd5" />

## 4. Verification Checklist Summary

| Verification Task | Command / Check | Status |
| :--- | :--- | :---: |
| Docker Engine Active | `docker run --rm hello-world` | ✅ Pass |
| AWS CLI v2 Installed | `aws --version` | ✅ Pass |
| Kubernetes CLI Ready | `kubectl version --client` | ✅ Pass |
| LocalStack Health | `curl http://localhost:4566/_localstack/health` | ✅ Pass |
| LocalStack STS Identity | `aws $EP sts get-caller-identity` | ✅ Pass |
| Kubernetes Cluster Ready | `kubectl get nodes` | ✅ Pass |

## 5. Conclusion

The local lab environment has been successfully deployed and verified[cite: 1]. All containerization platforms, local cloud emulators, and orchestrators are fully operational and prepared for upcoming lab exercises[cite: 1].
