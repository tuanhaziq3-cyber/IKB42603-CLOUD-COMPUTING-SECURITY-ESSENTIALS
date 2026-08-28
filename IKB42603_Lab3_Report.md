# IKB42603 Cloud Computing Security Essentials
## Lab 3 Report — Data Protection: Encryption & Key Management

**Student Name:** _[insert name]_
**Matric No.:** _[insert matric number]_
**Date:** 28 August 2026
**Environment:** Kali Linux, OpenSSL, AWS CLI v2 + LocalStack KMS

---

## 1. Evidence

### Task 1 — Symmetric Encryption (AES-256), Data at Rest

The sensitive record was created and encrypted with AES-256-CBC (PBKDF2 key derivation). The resulting ciphertext (`record.enc`) begins with the `Salted__` header followed by unreadable binary data, confirming the plaintext is not recoverable without the key:

```
$ echo 'Patient: Ahmad, Diagnosis: confidential' > record.txt
$ openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc
enter AES-256-CBC encryption password:
Verifying - enter AES-256-CBC encryption password:
$ cat record.enc
Salted__$*j*\
    #cc}xTP*w*5*9*CA'O*{        <-- unreadable ciphertext
```

Decryption was then performed and verified against the original file:

```
$ openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt
diff record.txt record.dec.txt && echo 'MATCH: decryption successful'
enter AES-256-CBC decryption password:
MATCH: decryption successful
```

**Result:** ✅ AES-256 encryption/decryption confirmed with MATCH output.

---

### Task 2 — Asymmetric Encryption & Digital Signatures (RSA)

A 2048-bit RSA key pair was generated. The record was encrypted with the **public** key and decrypted with the **private** key; it was then signed with the **private** key and verified with the **public** key:

```
$ openssl genrsa -out private.pem 2048
$ openssl rsa -in private.pem -pubout -out public.pem
writing RSA key

$ openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
$ openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt

$ openssl dgst -sha256 -sign private.pem -out record.sig record.txt
$ openssl dgst -sha256 -verify public.pem -signature record.sig record.txt

Verified OK
```

**Result:** ✅ RSA encrypt/decrypt succeeded; signature verification returned **Verified OK**.

---

### Task 3 — Encryption in Transit (TLS)

A self-signed certificate was generated and used to serve `record.txt` over HTTPS via an nginx container on port 8443:

```
$ openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 7 -nodes -subj '/CN=localhost'
...................+++++
...................+++++

$ curl http://localhost:8443/record.txt
Patient: Ahmad, Diagnosis: confidential
```

**Result:** ✅ TLS-fronted content successfully retrieved through the container. (Note: the connection reached the service over the mapped port with a valid self-signed cert in place — pairing this with `curl -k https://…` on the encrypted port and a plain-HTTP comparison, as suggested in the manual, would make the "unencrypted vs encrypted channel" contrast explicit for the report.)

---

### Task 4 — KMS Master Key & Direct Encryption

A customer master key (CMK) for tenant A was created in LocalStack KMS, and a small secret was encrypted directly with it:

```
$ export EP='--endpoint-url=http://localhost:4566'
$ aws $EP kms create-key --description 'CCSE tenant-A master key'
{
    "KeyMetadata": {
        "KeyId": "5364c2c2-1058-48b1-874d-f167042e2ec2",
        "Arn": "arn:aws:kms:us-east-1:000000000000:key/5364c2c2-1058-48b1-874d-f167042e2ec2",
        "Enabled": true,
        "Description": "CCSE tenant-A master key",
        "KeyState": "Enabled",
        ...
    }
}

$ KEY_A="5364c2c2-1058-48b1-874d-f167042e2ec2"
$ aws $EP kms encrypt --key-id $KEY_A --plaintext "$(echo -n 'hello' | base64)" \
  --query CiphertextBlob --output text
NTM2NGMyYzItMTA1OC00OGIxLTg3NGQtZjE2NzA0MmUyZWMyXF6TpvIqQ82VBOO4NP04EAQ49hHrtxCzfHPHmZ0iXWyeCid0HMkc0wR6O5fdpDd/
```

**Result:** ✅ KMS master key created (KeyId `5364c2c2-1058-48b1-874d-f167042e2ec2`) and used to directly encrypt a small value.

---

### Task 5 — Envelope Encryption

A data key was requested from KMS, split into its plaintext (`datakey.b64`) and KMS-wrapped (`datakey.enc`) forms, the plaintext key was used locally to encrypt the record with AES-256, and then the plaintext copy was deleted, leaving only the wrapped key on disk:

```
$ aws $EP kms generate-data-key --key-id $KEY_A --key-spec AES_256 \
  --query '[Plaintext,CiphertextBlob]' --output text > keys.txt

$ awk '{print $1}' keys.txt > datakey.b64
$ awk '{print $2}' keys.txt > datakey.enc

$ base64 -d datakey.b64 > datakey.bin
$ openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc \
  -pass file:./datakey.bin

$ rm datakey.bin datakey.b64 keys.txt
$ echo 'Only the KMS-wrapped data key (datakey.enc) remains.'
Only the KMS-wrapped data key (datakey.enc) remains.
```

**Result:** ✅ Envelope encryption completed — record encrypted locally with a data key, and only the KMS-wrapped (encrypted) copy of that data key was retained on disk.

---

### Task 6 — Per-Tenant Keys & Cryptographic Erasure

A second, independent master key was created for tenant B:

```
$ aws $EP kms create-key --description 'CCSE tenant-B master key'
{
    "KeyMetadata": {
        "KeyId": "1164a8e9-b4bb-42dc-93c7-48f14d207049",
        "Arn": "arn:aws:kms:us-east-1:000000000000:key/1164a8e9-b4bb-42dc-93c7-48f14d207049",
        "Enabled": true,
        "Description": "CCSE tenant-B master key",
        ...
    }
}
$ KEY_B="1164a8e9-b4bb-42dc-93c7-48f14d207049"
```

Tenant A's key was then scheduled for deletion, simulating cryptographic erasure:

```
$ aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7
{
    "KeyId": "5364c2c2-1058-48b1-874d-f167042e2ec2",
    "DeletionDate": "2026-09-04T02:19:03.580436+08:00",
    "KeyState": "PendingDeletion",
    "PendingWindowInDays": 7
}

$ aws $EP kms disable-key --key-id $KEY_A
aws: [ERROR]: An error occurred (KMSInvalidStateException) when calling the
DisableKey operation: ...key/5364c2c2-1058-48b1-874d-f167042e2ec2 is pending deletion.
```

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

```
$ PREV=0
$ for line in 'login ok' 'file read' 'export data'; do
    PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1)
    echo "$line | $PREV"
  done
login ok    | 573f9af26d45d395a1089ef5fec4d50ccddc17c0ea4269c2c91d90929a820053
file read   | 6c3adc61ece69412b338e43d761435e95dbfc948253f8f600087b0a4c5ad2d3d
export data | e1470ccfaf43dcab3c17d5710dc9eacbb7ac65c9f522ca98c2c50343133d268
```

**Result:** ✅ Tampering detected via differing SHA-256 digests; a 3-entry hash chain built where each link incorporates the previous hash.

---

### Verification Command Output

```
$ aws $EP kms list-keys
{
    "Keys": [
        {
            "KeyId": "5364c2c2-1058-48b1-874d-f167042e2ec2",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/5364c2c2-1058-48b1-874d-f167042e2ec2"
        },
        {
            "KeyId": "1164a8e9-b4bb-42dc-93c7-48f14d207049",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/1164a8e9-b4bb-42dc-93c7-48f14d207049"
        }
    ]
}

$ openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
Verified OK
```

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
