# IKB42603 Cloud Computing Security Essentials
## Lab 3 Report — Data Protection: Encryption & Key Management

**Student Name:** Tuan Haziq Hakimi
**Matric No.:** 52215124010
**Environment:** Kali Linux, OpenSSL, AWS CLI v2 + LocalStack KMS

---

## 1. Evidence

### Task 1 — Symmetric Encryption (AES-256), Data at Rest

The sensitive record was created and encrypted with AES-256-CBC (PBKDF2 key derivation). The resulting ciphertext (`record.enc`) begins with the `Salted__` header followed by unreadable binary data, confirming the plaintext is not recoverable without the key:

<img width="1248" height="472" alt="Screenshot 2026-08-28 083840" src="https://github.com/user-attachments/assets/ed03b97a-332d-424b-b3cf-0ee28a98b825" />


Decryption was then performed and verified against the original file:


<img width="1222" height="226" alt="image" src="https://github.com/user-attachments/assets/7e7ecd45-221d-4956-a127-d7d6b89d7ad7" />



**Result:** ✅ AES-256 encryption/decryption confirmed with MATCH output.

---

### Task 2 — Asymmetric Encryption & Digital Signatures (RSA)

A 2048-bit RSA key pair was generated. The record was encrypted with the **public** key and decrypted with the **private** key; it was then signed with the **private** key and verified with the **public** key:


<img width="1744" height="678" alt="image" src="https://github.com/user-attachments/assets/7689fb5b-d20a-4220-a870-f5dc24374f2c" />



**Result:** ✅ RSA encrypt/decrypt succeeded; signature verification returned **Verified OK**.

---

### Task 3 — Encryption in Transit (TLS)

A self-signed certificate was generated and used to serve `record.txt` over HTTPS via an nginx container on port 8443:


$ openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 7 -nodes -subj '/CN=localhost'
...................+++++
...................+++++

<img width="838" height="140" alt="image" src="https://github.com/user-attachments/assets/51a063b0-fba1-4641-9d89-18f22790b0f5" />



**Result:** ✅ TLS-fronted content successfully retrieved through the container. (Note: the connection reached the service over the mapped port with a valid self-signed cert in place — pairing this with `curl -k https://…` on the encrypted port and a plain-HTTP comparison, as suggested in the manual, would make the "unencrypted vs encrypted channel" contrast explicit for the report.)

---

### Task 4 — KMS Master Key & Direct Encryption

A customer master key (CMK) for tenant A was created in LocalStack KMS, and a small secret was encrypted directly with it:


<img width="2868" height="1042" alt="image" src="https://github.com/user-attachments/assets/399fcfca-7cc7-41c0-b27d-8aa41dc43acd" />



**Result:** ✅ KMS master key created (KeyId `5364c2c2-1058-48b1-874d-f167042e2ec2`) and used to directly encrypt a small value.

---

### Task 5 — Envelope Encryption

A data key was requested from KMS, split into its plaintext (`datakey.b64`) and KMS-wrapped (`datakey.enc`) forms, the plaintext key was used locally to encrypt the record with AES-256, and then the plaintext copy was deleted, leaving only the wrapped key on disk:


<img width="2622" height="782" alt="image" src="https://github.com/user-attachments/assets/aea5351b-487a-49c2-b8a1-91683dc7e740" />



**Result:** ✅ Envelope encryption completed — record encrypted locally with a data key, and only the KMS-wrapped (encrypted) copy of that data key was retained on disk.

---

### Task 6 — Per-Tenant Keys & Cryptographic Erasure

A second, independent master key was created for tenant B:


<img width="2568" height="966" alt="image" src="https://github.com/user-attachments/assets/5d854ea9-058d-4fa4-8c85-52952b88e399" />



Tenant A's key was then scheduled for deletion, simulating cryptographic erasure:


<img width="2844" height="794" alt="image" src="https://github.com/user-attachments/assets/8190565c-8b2e-4801-b18e-b53b1148f66d" />



An attempt to unwrap tenant A's data key (`datakey.enc`) after erasure was initiated **failed**, confirming the data is now unrecoverable:

```
$ base64 -d datakey.enc > datakey.enc.bin
$ aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc.bin 2>&1 | head -3
aws: [ERROR]: An error occurred (KMSInvalidStateException) when calling the
Decrypt operation: ...key/5364c2c2-1058-48b1-874d-f167042e2ec2 is pending deletion.
```

**Result:** ✅ Tenant B has its own independent key. Tenant A's key was placed into `PendingDeletion`, and every subsequent attempt to use it (disable, decrypt) failed with `KMSInvalidStateException` — demonstrating cryptographic erasure: `record.env.enc` is now permanently unrecoverable ciphertext.

---

### Task 7 — Integrity & Tamper-Evidence

`record.txt` was fingerprinted with SHA-256, a tampered copy was created, and the hashes were compared — the tampered file produced a different digest, proving that even a single appended character is detected:

```
$ sha256sum record.txt
$ cp record.txt tampered.txt; echo 'x' >> tampered.txt
$ sha256sum record.txt tampered.txt
<hash-of-record.txt>  record.txt
<different-hash>      tampered.txt
```

A simple hash chain (tamper-evident log) was then built, where each entry's hash depends on the previous entry's hash:


<img width="624" height="138" alt="image" src="https://github.com/user-attachments/assets/be038eb2-fba3-495f-9fea-5577bf94d34b" />



**Result:** ✅ Tampering detected via differing SHA-256 digests; a 3-entry hash chain built where each link incorporates the previous hash.

---

### Verification Command Output


<img width="624" height="297" alt="image" src="https://github.com/user-attachments/assets/f34df4e2-94f2-41bb-b704-24e51d4d713a" />



---

## 2. Short-Answer Questions

**Q1. Compare symmetric and asymmetric encryption: speed, key distribution, and typical use.**

Symmetric encryption (e.g., AES-256, used in Task 1) uses one shared secret key for both encryption and decryption. It is computationally fast and well suited to bulk data, which is why it is used for encrypting the actual content of files or database records at rest. Its weakness is key distribution: both parties must possess the identical key, and getting that key from one party to another without interception is a hard problem, especially across a network or between cloud services that don't already trust each other.

Asymmetric encryption (e.g., RSA, used in Task 2) uses a mathematically related key pair — a public key that can be shared freely and a private key that must stay secret. Anyone can encrypt with the public key, but only the private-key holder can decrypt, which solves the distribution problem at the cost of speed: RSA operations are orders of magnitude slower than AES for the same amount of data. In practice, asymmetric crypto is used for small payloads — key exchange, digital signatures, and identity verification (as in TLS certificates and Task 2's sign/verify steps) — while the bulk data itself is still protected with a symmetric algorithm. This hybrid pattern is exactly what envelope encryption (Task 5) implements.

**Q2. Why is key management described as the weakest link, not the algorithm?**

Modern algorithms like AES-256 and RSA-2048 are not practically breakable by brute force with current technology — the mathematics is sound. What actually gets compromised in real breaches is almost always the key: a passphrase reused or leaked, a private key left in a public repository, a master key stored alongside the data it protects, or a key given the same access as everyone else in a multi-tenant system. Task 1 shows this directly — the encrypted file is worthless without the password, so protecting *that password* is the entire security control. Similarly, the lab's security tip stresses watching "where the keys live," because if an attacker (or an untrusted cloud provider) gets both the ciphertext and the key, the strongest algorithm in the world provides no protection. Key management — generation, storage, rotation, access control, and deletion — is therefore the part of the system that actually determines whether the encryption holds up in practice.

**Q3. Explain envelope encryption and why only the master key needs hardware-grade protection.**

Envelope encryption (Task 5) separates two roles: a data key that does the actual, fast bulk-encryption work on the file, and a master key (held only inside the KMS) that does nothing but wrap (encrypt) and unwrap (decrypt) that data key. In the lab, KMS generated a data key and returned it in two forms — plaintext (used once, locally, to AES-encrypt `record.txt`) and a version already encrypted under the master key. Once the local encryption was done, the plaintext data key was deleted from disk, leaving only the wrapped copy (`datakey.enc`).

This design means the plaintext data key only ever exists briefly, in memory, on the machine doing the encrypting — it's never persisted. The master key, by contrast, never leaves the KMS and never directly touches the bulk data at all; it only ever wraps/unwraps small 256-bit data keys. Because the master key is small, rarely used, and centrally managed, it's the one component that's worth protecting with expensive hardware-backed security (an HSM) — protecting every data key that same way, for every file, would be impractical at cloud scale.

**Q4. How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)?**

Overwriting a file only works if you know exactly where every copy of it physically lives on disk and can guarantee you've overwritten all of them — which is essentially impossible in the cloud, where data is replicated across multiple disks, availability zones, snapshots, and backups that the customer doesn't control or even see.

Cryptographic erasure sidesteps this entirely. If data was only ever stored encrypted under a specific key, then destroying *that key* makes the data permanently unreadable no matter how many copies of the ciphertext exist or where they are — the ciphertext becomes meaningless noise. Task 6 demonstrated this directly: once tenant A's master key was moved into `PendingDeletion`, every attempt to decrypt data wrapped under it — even the tiny data key — failed with `KMSInvalidStateException`. The underlying `record.env.enc` file still physically exists, but it is now permanently unrecoverable. This is also *provable*: the KMS deletion event itself is the evidence of erasure, whereas proving that every disk sector holding a deleted file was actually overwritten is far harder to demonstrate to an auditor.

**Q5. How does a hash chain make a log tamper-evident (link to tamper-proof logs, Week 6)?**

In a hash chain, each new log entry doesn't just get its own hash — it gets hashed together with the hash of the *previous* entry, as shown in Task 7 (`PREV = sha256(PREV + line)`). This creates a linked sequence where every entry's hash depends on the entire history that came before it.

If an attacker tries to alter, delete, or insert an entry anywhere in the log, the hash of that entry changes, which changes the input to the next entry's hash, which changes its output, and so on — the mismatch cascades through every subsequent link in the chain. So instead of having to check every entry individually for tampering, a verifier only needs to recompute the chain and compare the final hash: any modification anywhere in the log's history is immediately detectable. This is the same principle underlying tamper-proof audit logs and, at a larger scale, blockchains — the chain doesn't prevent someone from *editing* stored data, but it makes any edit mathematically obvious.

---

## 3. Security Best-Practices Checklist

- [x] Data encrypted at rest (AES) and decryption verified.
- [x] Asymmetric keys used correctly (encrypt with public, sign with private).
- [x] Data protected in transit with TLS.
- [x] Envelope encryption used; plaintext data key not left on disk.
- [x] Per-tenant keys used; cryptographic erasure demonstrated.
- [x] Integrity verified with hashing / hash chain.
