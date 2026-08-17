# IKB42603 Cloud Computing Security Essentials — Lab 2 Report
## Secure Isolation & Multi-Tenancy (Compute, Network, and Storage Isolation with Docker & Kubernetes)

**Course:** IKB42603 Cloud Computing Security Essentials
**Institution:** UniKL MIIT
**Lab:** Lab 2, Weeks 3–4
**CLO Mapping:** CLO2 — Construct secure cloud operations that safeguard data integrity
**Value/Skill Clusters:** VBE3 (Integrity), SC8 (Integrated Problem-Solving)

---

## 1. Objective

This lab demonstrates isolation controls in a shared, multi-tenant Kubernetes cluster by:

1. Modelling two tenants as separate namespaces on shared infrastructure.
2. Proving that cross-tenant traffic is allowed by default ("default-open" risk).
3. Containing noisy-neighbour resource consumption with a `ResourceQuota`.
4. Enforcing network isolation with a default-deny `NetworkPolicy` and re-proving the same probe now fails.
5. (Session B continuation) Enforcing storage/secret isolation via RBAC and demonstrating data remanence.

## 2. Environment Setup

A local `kind` cluster was created with the default CNI disabled so that Calico could be installed to actually enforce `NetworkPolicy` objects (the default kind network does not enforce policies).

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
```

**Screenshot — cluster creation:**

![kind cluster creation](./assets/task1-cluster-creation.png)

Calico was then installed and its DaemonSet rollout was confirmed as ready before proceeding.

**Screenshot — Calico installation:**

![Calico installation](./assets/task1-calico-install.png)

---

## 3. Session A (Week 3) — Compute Isolation & the Default-Open Risk

### Task 1 — Two Tenants on One Cluster

Two namespaces, `tenant-a` and `tenant-b`, were created to model two customers sharing the same physical cluster. An `nginx` deployment was created and exposed as a `ClusterIP` Service in each namespace.

**Screenshot — namespaces, deployments, and services:**

![Namespaces and deployments](./assets/task1-namespaces-deployments.png)

### Task 2 — Observe the Default-Open Risk

A temporary probe pod (`curlimages/curl`) was launched in `tenant-a` and used to reach `tenant-b`'s Service ClusterIP directly.

**Result: `HTTP 200`** — confirming that, by default, pods in one namespace **can** freely reach pods/services in another namespace on shared infrastructure.

**Screenshot — cross-tenant probe (before isolation):**

![Cross-tenant HTTP 200](./assets/task2-cross-tenant-http200.png)

> **Observation:** Isolation between tenants is **not automatic** on a shared Kubernetes cluster. Namespaces alone provide a logical grouping/naming boundary, not a network security boundary.

### Task 3 — Contain the Noisy Neighbour (Resource Quotas)

A `ResourceQuota` was applied to `tenant-a` to cap total CPU requests to 1 core, memory requests to 512Mi, and the pod count to 5 — preventing one tenant from exhausting shared node capacity.

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
```

**Screenshot — ResourceQuota applied:**

![ResourceQuota applied](./assets/task3-resourcequota.png)

---

## 4. Session B (Week 4) — Network & Storage Isolation

### Task 4 — Default-Deny Network Isolation

A default-deny ingress `NetworkPolicy` was applied to `tenant-b`, blocking all inbound traffic to pods in that namespace unless explicitly allowed:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
```

**Screenshot — NetworkPolicy applied:**

![NetworkPolicy applied](./assets/task4-networkpolicy-applied.png)

The **same probe** from Task 2 was re-run from `tenant-a` against `tenant-b`'s Service IP.

**Result: `HTTP 000` (connection timeout)** — the request that previously returned `HTTP 200` now fails to connect at all, confirming that Calico is enforcing the default-deny `NetworkPolicy` and cross-tenant traffic is blocked.

**Screenshot — before/after verification (quota removed/re-applied around the retest):**

![Before/after probe result](./assets/task4-before-after-probe.png)

| Stage | Command | Result |
|---|---|---|
| Before `NetworkPolicy` (Task 2) | `curl http://<tenant-b ClusterIP>` from `tenant-a` | `HTTP 200` (reached) |
| After `NetworkPolicy` (Task 4) | Same command, same target | `HTTP 000` (timed out / blocked) |

### Task 5 — Storage & Secret Isolation

A Secret was created in each namespace, and a `ServiceAccount` (`app-a`) scoped to `tenant-a` was granted a `Role`/`RoleBinding` permitting `get` on Secrets **only within `tenant-a`**.

```bash
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B

kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a

SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA   # expected: yes
kubectl auth can-i get secrets -n tenant-b --as=$SA   # expected: no
```

**Result:** `kubectl auth can-i` returned **`yes`** for `tenant-a` and **`no`** for `tenant-b`, confirming that the `tenant-a`-scoped ServiceAccount can read its own namespace's Secret but is denied access to `tenant-b`'s Secret — RBAC-enforced storage/secret isolation.

**Screenshot — RBAC secret isolation (`can-i` yes/no):**

![RBAC secret isolation](./assets/task5-rbac-secret-isolation.png)

### Task 6 — Data Remanence & Secure Deletion

A file containing `SENSITIVE-PATIENT-RECORD` was written to a Docker volume, deleted normally with `rm`, and the volume was then scanned with `grep` for the residual text. A second file was securely wiped — overwritten with zero bytes via `dd` — before deletion.

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
   grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'

docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
   dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
   echo wiped'
```

**Result:** The scan completed (`scan-done`) with no `SENSITIVE` text returned by `grep` — because `rm` removes the directory entry, `/data/*` no longer glob-matches the deleted file, so a simple in-container `grep` cannot demonstrate raw-block remanence (that would require scanning the underlying block device directly, which is outside the container's visibility). The secure-wipe file was overwritten with zeroes via `dd` and then removed, completing with `wiped`.

**Screenshot — remanence scan, secure wipe, and verification commands:**

![Data remanence and verification](./assets/task6-remanence-and-verification.png)

This screenshot also captures the **Section 6 verification commands** output: `kubectl get networkpolicy -A` confirms `default-deny-ingress` exists in `tenant-b`, and `kubectl describe resourcequota tenant-a-quota -n tenant-a` confirms the quota's hard limits (`pods: 5`, `requests.cpu: 1`, `requests.memory: 512Mi`).

---

## 5. Short-Answer Questions

**Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?**

Kubernetes namespaces are primarily a **logical/administrative boundary** (naming, RBAC scoping, resource quotas) — they are not a network security boundary. Unless a CNI that enforces `NetworkPolicy` is installed and a policy is actually applied, the pod network is flat: any pod can route to any other pod's IP or ClusterIP regardless of namespace. In a multi-tenant cloud, this "default-open" behaviour is dangerous because a compromised or malicious workload belonging to one tenant can freely probe, connect to, or attack another tenant's services, defeating the isolation the tenants are paying for and potentially exposing sensitive data or enabling lateral movement.

**Q2. Explain the default-deny principle and how your NetworkPolicy implements it.**

Default-deny is a segmentation principle stating that **all traffic should be blocked unless explicitly permitted** — the inverse of the flat, default-open network. In this lab, applying a `NetworkPolicy` with an empty `podSelector: {}` and `policyTypes: [Ingress]` in `tenant-b` selects *all* pods in that namespace and, because no `ingress` rules are listed, denies *all* inbound traffic to them. The before/after probe demonstrated this directly: the identical `curl` request that succeeded (`HTTP 200`) before the policy was applied failed to connect (`HTTP 000`) after it was applied, proving that only explicitly allowed traffic (which we did not add) would now be permitted.

**Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?**

Containers share the host operating system's kernel and are isolated using Linux namespaces, cgroups, and (optionally) additional sandboxing — this is lightweight but means a kernel-level exploit can potentially let one container affect others or the host. Virtual machines each run their own guest kernel on top of a hypervisor, so the isolation boundary is enforced by hardware-assisted virtualization, which is considerably stronger against kernel-level and side-channel attacks. A VM boundary (or a stronger container sandbox such as gVisor/Kata Containers, or dedicated node pools per tenant) should be added when tenants are mutually untrusted, when workloads run arbitrary or untrusted code, when regulatory/compliance requirements mandate hardware-level separation, or when the blast radius of a container-escape needs to be limited to a single tenant.

**Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?**

Data remanence is the residual representation of data that persists on storage media even after it has been "deleted" through normal filesystem operations — the file system typically only removes the pointer/reference to the data and marks the space as free, leaving the actual bytes recoverable until they are overwritten. In cloud environments, tenants and even providers rarely have control over the physical storage blocks (which may be replicated, snapshotted, wear-levelled on SSDs, or reused across abstraction layers), so a low-level secure-wipe of physical media is often impractical or impossible to guarantee. **Cryptographic erasure** — encrypting data at rest and then destroying the encryption key — is preferred because it makes the data permanently unrecoverable regardless of where or how many copies of the underlying ciphertext exist, without requiring access to or control over the physical storage medium.

**Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?**

| Task | Isolation Dimension |
|---|---|
| Task 1 — Two tenants as namespaces | Compute |
| Task 2 — Observe default-open risk | Network |
| Task 3 — Resource quotas (noisy neighbour) | Compute |
| Task 4 — Default-deny NetworkPolicy | Network |
| Task 5 — Secret isolation via RBAC | Storage |
| Task 6 — Data remanence & secure deletion | Storage |

---

## 6. Verification Commands

```bash
kubectl get networkpolicy -A
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

## 7. Security Best-Practices Checklist

- [x] Tenants are separated into distinct namespaces.
- [x] A default-deny NetworkPolicy blocks cross-tenant traffic (verified before/after).
- [x] Resource quotas prevent a noisy-neighbour from exhausting shared capacity.
- [x] Per-tenant secrets are unreadable by other tenants (RBAC enforced).
- [x] Secure deletion / cryptographic erasure is understood for data remanence.

## 8. Cleanup & Teardown

```bash
kind delete cluster --name ccse-lab2
docker volume rm ccse-vol
```

## 9. Conclusion

This lab demonstrated, with direct evidence, that Kubernetes namespaces alone do **not** provide network isolation between tenants on shared infrastructure — cross-namespace traffic succeeds by default. Applying a default-deny `NetworkPolicy` (enforced by the Calico CNI) closed this gap, changing the identical cross-tenant request from `HTTP 200` to a timeout. A `ResourceQuota` was used to contain compute consumption per tenant, addressing the "noisy neighbour" risk. RBAC scoping proved that a tenant's ServiceAccount can read only its own Secrets (`yes`/`no` on `kubectl auth can-i`), and the data-remanence exercise showed how "deleted" data is handled at the filesystem level versus a secure overwrite. Together, this lab covers all three isolation dimensions — compute, network, and storage — required for safe multi-tenancy in the cloud.

---

### Repository Structure

```
.
├── LAB2_Secure_Isolation_and_Multitenancy_Report.md
└── assets/
    ├── task1-cluster-creation.png
    ├── task1-calico-install.png
    ├── task1-namespaces-deployments.png
    ├── task2-cross-tenant-http200.png
    ├── task3-resourcequota.png
    ├── task4-networkpolicy-applied.png
    ├── task4-before-after-probe.png
    ├── task5-rbac-secret-isolation.png
    └── task6-remanence-and-verification.png
```

*Place this file at the root of your GitHub repository (or in a `reports/` folder) alongside an `assets/` folder containing the screenshots above so the images render correctly on GitHub.*
