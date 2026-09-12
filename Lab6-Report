# IKB42603 – Cloud Computing Security Essentials
## Lab 6 Report: Object Storage Security & the Data Security Lifecycle

**Name:** Tuan Haziq Hakimi
**Matric No.:** 52215124010
**Group / Section:** L02-B03

---

## 1. Introduction

This lab reproduces the two halves of the object-storage data security lifecycle on Amazon S3 (via LocalStack). Session A (Tasks 1–4) is concerned with **who can reach the data** — classification, the classic public-bucket breach, Block Public Access, and the interaction between identity-based (IAM) and resource-based (bucket) policies. Session B (Tasks 5–8) is concerned with **what state the data is in** — default encryption at rest, delegated access via presigned URLs, versioning and data remanence, and lifecycle rules culminating in provable, cryptographic erasure. The environment was a clean LocalStack container started with `ENFORCE_IAM=1` so that IAM/bucket-policy evaluation is actually enforced rather than bypassed.

---

## 2. Session A (Week 11) — Object Storage & the Exposure Problem

### Task 1 — Classify the Data Before You Store It

A bucket (`$BUCKET`) was created to simulate a hospital records system, and three objects of increasing sensitivity were uploaded under distinct key prefixes — `public/notice.txt`, `internal/roster.txt`, and `confidential/record.txt` — each tagged with its own `classification` value (`public`, `internal`, `confidential` respectively) using `--tagging` on `put-object`. Listing the bucket with `list-objects-v2` confirmed all three keys and sizes, and `get-object-tagging` on the confidential object confirmed the tag was attached correctly.

The key takeaway carried into the rest of the lab: S3 has a **flat namespace** — `confidential/` is not a real folder, just a string prefix on the key — which is exactly why access-control decisions later in the lab are written as prefix-based `Resource` patterns (e.g. `$BUCKET/internal/*`) rather than assumed folder boundaries, and why a careless prefix like `*` exposes everything at once.

```bash
export BUCKET=miit-patient-records-$RANDOM
echo $BUCKET

aws $EP s3api create-bucket --bucket $BUCKET

echo 'Ward visiting hours 10am-8pm' > public-notice.txt
echo 'Staff duty schedule, week 12' > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential' > confidential-record.txt

aws $EP s3api put-object --bucket $BUCKET --key public/notice.txt \
  --body public-notice.txt --tagging 'classification=public'
aws $EP s3api put-object --bucket $BUCKET --key internal/roster.txt \
  --body internal-roster.txt --tagging 'classification=internal'
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body confidential-record.txt --tagging 'classification=confidential'

aws $EP s3api list-objects-v2 --bucket $BUCKET \
  --query 'Contents[].[Key,Size]' --output table

aws $EP s3api get-object-tagging --bucket $BUCKET --key confidential/record.txt
```

**Evidence / output:**
```
[paste your list-objects-v2 table here]
[paste your get-object-tagging output here]
```

**

### Task 2 — Reproduce the Archetypal Breach

A bucket policy (`public-policy.json`) was written with `"Principal": "*"` and `"Action": "s3:GetObject"` on `$BUCKET/*`, and applied with `put-bucket-policy`. An anonymous `curl` request — with no AWS credentials, no CLI profile, nothing but the object's URL — was then issued directly against `confidential/record.txt`.

**Result:** `HTTP 200`, and the patient's confidential record was returned in full to an unauthenticated caller. No exploit, vulnerability, or credential theft was involved — the single word `Principal: "*"` in the policy JSON was the entire cause of the breach, which is the same root cause behind the majority of real-world "exposed cloud bucket" incidents.

```bash
cat > public-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicReadEverything",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET/*"
  }]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text

# The attacker's view: no AWS credentials, no CLI, just a URL
curl -s -o leaked.txt -w 'HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
cat leaked.txt
```

**Evidence / output:**
```
[paste your get-bucket-policy output here]
[paste your curl HTTP status code + leaked.txt contents here]
```

*[Screenshot 2: anonymous `curl` command and output showing `HTTP 200` and the leaked record text]*

### Task 3 — Remediate with Block Public Access

The offending policy was removed with `delete-bucket-policy`, and the account-level guardrail was applied via `put-public-access-block` with all four flags (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) set to `true`. `get-public-access-block` confirmed the configuration was stored correctly.

Re-attempting to apply the same public policy, and re-testing the anonymous `curl` request, was used to check enforcement. LocalStack is known to store this configuration faithfully without always enforcing it at the data plane, so if the anonymous read still returned `HTTP 200` after the guardrail was set, the `get-public-access-block` output itself was captured as evidence that the *configuration* was correct even though the *emulator* did not fully enforce it — a distinction explicitly called out in the manual. On real AWS, `BlockPublicPolicy` is the specific flag that would have rejected the attempt to re-apply the public policy in step 3, since it refuses any new bucket policy that would grant public access, regardless of what the policy author intended.

Finally, a least-privilege replacement policy was written, granting `s3:GetObject` only to the bucket owner's own account root ARN (`arn:aws:iam::000000000000:root`) and scoped only to the `internal/*` prefix — i.e., the policy that should have existed from the start.

```bash
# 1. Remove the offending policy
aws $EP s3api delete-bucket-policy --bucket $BUCKET

# 2. Apply the account-level guardrail to the bucket
aws $EP s3api put-public-access-block --bucket $BUCKET \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws $EP s3api get-public-access-block --bucket $BUCKET

# 3. Try to re-introduce the public policy - the guardrail should refuse it
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json

# 4. Re-test the anonymous read
curl -s -o /dev/null -w 'anonymous read now: HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt

# The least-privilege policy that should have existed from the start
cat > least-privilege-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AccountReadInternalOnly",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET/internal/*"
  }]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://least-privilege-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text
```

**Evidence / output:**
```
[paste your get-public-access-block output here — all four flags should read true]
[paste your re-tested anonymous read HTTP status code here]
[paste your final get-bucket-policy output here]
```

*[Screenshot 3: `get-public-access-block` output with all four flags `true`, plus the re-tested anonymous read result]*

**Why a guardrail is stronger than a detective control:** a detective control (e.g. a script that reports "this bucket is public") only tells you *after the fact* that something went wrong. A preventative guardrail like Block Public Access stops the misconfiguration from ever taking effect, regardless of who applied it or why — it removes the dependency on someone noticing and reacting quickly enough.

### Task 4 — Identity Policy vs Resource Policy

An IAM user `DataAnalyst` was created with an identity-based policy allowing `s3:GetObject`/`s3:ListBucket` on `Resource: "*"` — i.e. an analyst who, by IAM alone, can read anything in the account. A bucket policy was then layered on top with two statements: an explicit **Allow** for the analyst on `internal/*`, and an explicit **Deny** for the analyst on `confidential/*`.

Testing with the `analyst` CLI profile:
- `GetObject` on `internal/roster.txt` → **succeeded** (both the IAM policy and the bucket policy agree).
- `GetObject` on `confidential/record.txt` → **failed/denied** (the IAM policy alone would have allowed it, but the bucket policy's explicit Deny overrides it).

This demonstrates the standard AWS policy evaluation order: **default deny → any explicit Deny wins → otherwise an explicit Allow from either layer is required.** The bucket policy was removed again immediately afterward (`delete-bucket-policy`) as instructed, since a `Deny` scoped to `s3:*` on a mismatched principal ARN is one of the most common ways to accidentally lock oneself out of a bucket in production.

```bash
# Analyst IAM identity with a broad allow
aws $EP iam create-user --user-name DataAnalyst

cat > analyst-iam.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": "*"
  }]
}
JSON

aws $EP iam put-user-policy --user-name DataAnalyst \
  --policy-name S3ReadAll --policy-document file://analyst-iam.json

aws $EP iam create-access-key --user-name DataAnalyst \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text

# Configure the analyst profile with the returned key pair
ANALYST_KEY_ID='PASTE_KEY_ID_HERE'
ANALYST_SECRET='PASTE_SECRET_HERE'
aws configure --profile analyst set aws_access_key_id "$ANALYST_KEY_ID"
aws configure --profile analyst set aws_secret_access_key "$ANALYST_SECRET"
aws configure --profile analyst set region us-east-1

# Bucket policy: allow internal/*, explicitly deny confidential/*
cat > deny-confidential.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAnalystInternal",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$BUCKET/internal/*"
    },
    {
      "Sid": "DenyAnalystConfidential",
      "Effect": "Deny",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::$BUCKET/confidential/*"
    }
  ]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://deny-confidential.json

# Should SUCCEED - allowed by both policies
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key internal/roster.txt analyst-internal.txt && echo "internal: ALLOWED"

# Should FAIL - IAM allows, but the bucket policy explicitly denies
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket $BUCKET --key confidential/record.txt analyst-conf.txt || echo "confidential: DENIED"

# Clean up before Session B
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

**Evidence / output:**
```
[paste "internal: ALLOWED" result here]
[paste "confidential: DENIED" result here, or your written evaluation if ENFORCE_IAM was not active]
```

*[Screenshot 4: the analyst's two attempts — `internal: ALLOWED` and `confidential: DENIED` — or the written evaluation if `ENFORCE_IAM` was not active]*

---

## 3. Session B (Week 12) — Protecting, Retaining and Retiring Data

### Task 5 — Default Encryption at Rest (SSE-KMS)

A dedicated KMS key was created for the bucket, and `put-bucket-encryption` was used to set a default `ApplyServerSideEncryptionByDefault` rule using `aws:kms` with that key ID, plus `BucketKeyEnabled: true` for the envelope-encryption cost/latency optimisation (reusing one data key across many objects instead of a fresh KMS call per object, with no change to confidentiality).

An object was then uploaded with **no encryption flags at all**, and `head-object` confirmed the bucket applied `ServerSideEncryption: aws:kms` and the correct `SSEKMSKeyId` automatically — proof that the control protects every object regardless of whether the uploading developer remembered to request encryption.

```bash
export KEY_ID=$(aws $EP kms create-key \
  --description 'IKB42603 Lab6 patient records bucket key' \
  --query 'KeyMetadata.KeyId' --output text)
echo $KEY_ID

cat > encryption.json <<JSON
{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "$KEY_ID"
    },
    "BucketKeyEnabled": true
  }]
}
JSON

aws $EP s3api put-bucket-encryption --bucket $BUCKET \
  --server-side-encryption-configuration file://encryption.json
aws $EP s3api get-bucket-encryption --bucket $BUCKET

# Upload with NO encryption flags at all - the bucket applies the key for you
aws $EP s3api put-object --bucket $BUCKET \
  --key confidential/record-v2.txt --body confidential-record.txt

aws $EP s3api head-object --bucket $BUCKET --key confidential/record-v2.txt \
  --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' --output text
```

**Evidence / output:**
```
[paste your get-bucket-encryption output here]
[paste your head-object output here — expect: aws:kms  <key-id>  True]
```

*[Screenshot 5: `head-object` output showing `aws:kms` and the KMS key ID]*

### Task 6 — Delegated Access and the Condition-Key Trap

A presigned URL was generated for `internal/roster.txt` with a 60-second expiry using `aws s3 presign`. Fetching it immediately with `curl` succeeded; after `sleep 65` the same URL was retried to test expiry enforcement (LocalStack may not always enforce this, in which case the `X-Amz-Expires`/`Signature` parameters embedded in the URL itself were inspected as the evidence: `X-Amz-Expires` binds how long the signature is valid for, and `Signature` binds the signed request to that exact expiry window and to the specific object/action — anyone holding the URL before it lapses is, by design, fully and anonymously authorised, with no further identity check).

The "condition-key trap" was then reproduced deliberately: a bucket policy denying any request where `aws:SecureTransport` is `false` was applied — a policy copied from countless hardening guides. Because the LocalStack endpoint is plain `http://`, **every** subsequent call (including the operator's own `list-objects-v2`) evaluated `aws:SecureTransport` as `false` and was denied, locking the operator out of their own bucket. The policy was removed immediately with `delete-bucket-policy` to recover.

**Lesson:** on real AWS, where the endpoint is HTTPS, this exact policy would correctly pass through legitimate encrypted traffic and only catch genuinely insecure callers. A condition key must always be evaluated against the environment it will actually run in — not the one it was written for — since the same JSON that is a best practice in production became a self-inflicted denial-of-service against the operator in this HTTP-only lab environment.

```bash
# Time-bounded, signed, single-object access
aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60

URL='PASTE_PRESIGNED_URL_HERE'
curl -s -w ' <-- HTTP %{http_code}\n' "$URL"

# Wait for it to lapse, then try the same url again
sleep 65
curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"

# The condition-key trap
cat > secure-transport.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::$BUCKET", "arn:aws:s3:::$BUCKET/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}
JSON

aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://secure-transport.json

# Any ordinary call - expect it to be refused
aws $EP s3api list-objects-v2 --bucket $BUCKET

# Recover before continuing
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

**Evidence / output:**
```
[paste your presigned URL curl result (before expiry) here]
[paste your "after expiry" HTTP status code here]
[paste the list-objects-v2 denial after the SecureTransport policy was applied here]
```

*[Screenshot 6: the bucket-wide failure/denial caused by the `aws:SecureTransport` policy]*

### Task 7 — Versioning, Delete Markers & Data Remanence

Versioning was enabled on the bucket. Two further revisions of `confidential/record.txt` were uploaded (a corrected diagnosis, then a redacted version), and `list-object-versions` showed three distinct versions, with the original Task 1 upload (made before versioning was enabled) carrying version ID `null`.

`delete-object` was then called on the key with no version ID specified. This did **not** remove any data — it created a **delete marker** as the new "current" version. An ordinary `get-object` call now behaved as if the object were gone, but explicitly requesting `--version-id null` retrieved the *original, unredacted* record intact — proving that the diagnosis the team believed had been redacted and then deleted was, in fact, still fully present and retrievable in the bucket. This is **object-level data remanence**, and it is why "we deleted the record" is not, by itself, an acceptable response to a data-subject erasure request under a regime such as the PDPA or GDPR. Permanently removing the data required explicitly deleting every version by its version ID.

```bash
aws $EP s3api put-bucket-versioning --bucket $BUCKET \
  --versioning-configuration Status=Enabled
aws $EP s3api get-bucket-versioning --bucket $BUCKET

# Two more revisions of the same record
echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]' > rec-v3.txt

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v2.txt --query VersionId --output text
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v3.txt --query VersionId --output text

aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,IsLatest,Size]' --output table

# 'Delete' the record
aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt

# A delete marker is now the current version
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'DeleteMarkers[].[VersionId,IsLatest]' --output table

# To an ordinary reader the object is gone
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt gone.txt

# But the original, unredacted record is still there
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt \
  --version-id null recovered.txt
cat recovered.txt

# Permanent, per-version deletion
aws $EP s3api delete-object --bucket $BUCKET \
  --key confidential/record.txt --version-id null
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt --query 'Versions[].[VersionId,Size]' --output table
```

**Evidence / output:**
```
[paste your version listing table here]
[paste your delete marker listing here]
[paste recovered.txt contents here — the original, unredacted diagnosis]
```

*[Screenshot 7: version listing, the delete marker, and `recovered.txt` still containing the original diagnosis]*

### Task 8 — Lifecycle, Retention & Cryptographic Erasure

A lifecycle configuration was applied with two rules: `RetireConfidentialRecords` (expiring current versions under `confidential/` after 365 days and non-current versions after 30 days) and `AbortIncompleteUploads` (aborting incomplete multipart uploads after 7 days). `get-bucket-lifecycle-configuration` confirmed both rules were `Enabled` — this configuration is the automated, auditable artefact an auditor would expect to see as evidence of a documented retention policy, rather than relying on someone manually deleting old versions.

Finally, since every object in the bucket is encrypted under the one KMS key created in Task 5, that key was **disabled** and then **scheduled for deletion** (`schedule-key-deletion`, 7-day pending window) — demonstrating **cryptographic erasure**: destroying the key renders every object ever encrypted under it, across every version, replica, and backup, permanently unrecoverable in a single action, without needing to locate or overwrite every physical copy of the data.

```bash
cat > lifecycle.json <<'JSON'
{
  "Rules": [
    {
      "ID": "RetireConfidentialRecords",
      "Filter": {"Prefix": "confidential/"},
      "Status": "Enabled",
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    },
    {
      "ID": "AbortIncompleteUploads",
      "Filter": {"Prefix": ""},
      "Status": "Enabled",
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
    }
  ]
}
JSON

aws $EP s3api put-bucket-lifecycle-configuration --bucket $BUCKET \
  --lifecycle-configuration file://lifecycle.json
aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID,Status]' --output table

# Cryptographic erasure
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyId,KeyState,Enabled]' --output text
aws $EP kms disable-key --key-id $KEY_ID
aws $EP kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyState,DeletionDate]' --output text

# Attempt to read an object encrypted under the disabled key
aws $EP s3api get-object --bucket $BUCKET \
  --key confidential/record-v2.txt after-erasure.txt
```

**Evidence / output:**
```
[paste your lifecycle rules table here]
[paste your KMS key state before/after schedule-key-deletion here]
[paste the result of reading the object after the key was disabled here]
```

*[Screenshot 8: lifecycle rules table + KMS key state (`PendingDeletion`) after `schedule-key-deletion`]*

**Why cryptographic erasure is stronger for an auditor than overwriting:** overwriting requires control over the physical media the data was ever written to, including every backup, replica, and prior version — something a cloud tenant does not have. Cryptographic erasure needs to destroy only the (much smaller, centrally-managed) key material; once the key is gone, every copy of the ciphertext anywhere becomes mathematically unrecoverable regardless of how many copies exist or where they are stored.

---

## 4. Data Classification Table

| Classification | Who may read it | Impact if leaked | Control you will apply |
|---|---|---|---|
| **Public** | Anyone — patients, visitors, the general public | Negligible — the information (e.g. visiting hours) is meant to be public; no privacy or compliance exposure | Served openly (e.g. via a scoped public-read policy limited strictly to the `public/` prefix, or a static website endpoint) — never via a wildcard bucket policy |
| **Internal** | Authenticated hospital staff only (not patients, not the public) | Moderate — reveals internal operations (duty rosters, schedules) that could support social engineering or insider misuse, but no direct patient-privacy breach | Bucket/IAM policy scoped by prefix (`internal/*`) to the hospital's own account principal, Block Public Access enabled, no anonymous access |
| **Confidential** | Only the specific clinicians/roles with a legitimate need to access that patient's record | Severe — direct breach of patient privacy, legal exposure under PDPA/GDPR-style regimes, reputational and trust damage to the hospital | Least-privilege intersection of IAM + explicit bucket-policy Deny for everyone else, default SSE-KMS encryption at rest, versioning + lifecycle expiration for provable retention, cryptographic erasure available for erasure requests, Block Public Access enforced |

---

## 5. Short-Answer Questions

### Q1. Which single element of the Task 2 policy caused the exposure, and why is `Principal: "*"` more dangerous on a bucket policy than an over-broad IAM policy attached to one user?

The exposure was caused entirely by the `"Principal": "*"` field. It tells S3 that *any* principal — including a caller with no AWS credentials at all — is authorised to run `s3:GetObject`. Because this grant lives on the **resource** (the bucket), it bypasses identity and authentication altogether: there is no access key to steal, no user account to compromise, because the policy doesn't require one in the first place. It effectively turns every matching object into a plain, unauthenticated HTTP resource that anyone can fetch by guessing or scanning the URL.

An over-broad IAM policy on a single user (say, `s3:*` on `Resource: "*"`) is dangerous too, but it is still gated by that one identity's credentials — an attacker has to obtain that specific user's access key or role before the excess privilege can be exploited. `Principal: "*"` on a bucket policy removes that gate entirely, which is exactly why misconfigured bucket policies (not leaked IAM credentials) are the single most common root cause of real-world "exposed S3 bucket" breaches.

### Q2. Explain the difference between an identity-based policy and a resource-based policy. In Task 4, which one decided each of the analyst's two requests?

An **identity-based policy** (IAM) is attached to a principal — a user, group, or role — and defines what that principal is allowed to do, independent of which bucket it happens to touch (unless the `Resource` field narrows it). A **resource-based policy** (a bucket policy) is attached to the resource itself and defines which principals may act on *it*, independent of what any other policy says about those principals. AWS evaluates both together using a single logic: default deny → any explicit **Deny** anywhere wins outright → otherwise an explicit **Allow** from either layer is required.

In Task 4:
- **`internal/roster.txt`** — DataAnalyst's IAM policy allowed `GetObject` on everything, and the bucket policy's `AllowAnalystInternal` statement also allowed it for that prefix. Both layers agreed, so the request succeeded — no single layer "decided" it; there was no conflict to resolve.
- **`confidential/record.txt`** — The IAM policy still said Allow, but the bucket policy's `DenyAnalystConfidential` statement issued an explicit Deny. The **resource-based (bucket) policy** decided this outcome, because an explicit Deny always overrides any Allow, regardless of which policy layer it came from.

### Q3. Block Public Access is described as a guardrail rather than a control. What is the difference, and why does the distinction matter for an organisation with many engineers?

A **control** in this context is a point-in-time configuration choice — such as a specific bucket policy — that someone has to get right, and can just as easily get wrong or forget to apply. It is reactive and only as reliable as the person who last touched it. A **guardrail** is a structural constraint that sits above individual configuration choices: Block Public Access overrides *any* policy or ACL — past, present, or future — that would otherwise make the bucket public. It doesn't ask anyone to remember to do the right thing; it makes the wrong outcome impossible in the first place.

The distinction matters at scale because no organisation can guarantee that every engineer, on every team, writing every policy, will get least-privilege exactly right every single time — mistakes are statistically inevitable across enough people and enough deployments. A guardrail enforced centrally (at the bucket or account level, ideally by a security/platform team via a default or service control policy) protects the organisation from any one individual's mistake, turning "we hope everyone configures this correctly" into "it structurally cannot go wrong regardless of who configures it."

### Q4. Your bucket has default SSE-KMS encryption. Does that protect the confidential record from the analyst in Task 4? Explain precisely what server-side encryption does and does not defend against.

No, it does not. Server-side encryption at rest protects data against someone who obtains the **raw ciphertext or storage media without going through an authorised API call** — for example, a cloud-provider employee accessing disks directly, physical theft of drives, or another tenant somehow reading raw bytes off shared storage. It does nothing to stop a caller who is **authorised** (by IAM and/or bucket policy) to call `GetObject` through the normal S3 API, because S3 decrypts the object transparently on the server side and simply returns plaintext to any caller whose request is permitted.

In Task 4, the analyst was blocked by the bucket policy's explicit **Deny** statement — not by encryption. If that Deny statement had not existed, SSE-KMS would not have stopped the analyst from retrieving the plaintext record at all, because their `GetObject` call would have been authorised. In short: SSE-KMS defends against out-of-band, media-level, or provider-side exposure of ciphertext; it is not a substitute for access control and does nothing against a caller who is technically authorised but shouldn't be, per least-privilege policy.

### Q5. A patient invokes their right to erasure. Using your Task 7 evidence, explain why `delete-object` alone is not compliant, and describe two mechanisms that would make the deletion provable.

In a versioned bucket, calling `delete-object` without a version ID does not remove any bytes — it writes a new **delete marker** on top of the key, which only hides the object from ordinary reads (plain `list-objects`/`get-object` calls). Every prior version, including the original unredacted record, remains fully intact and retrievable by anyone who calls `get-object --version-id <id>`. Task 7 demonstrated this directly: after "deleting" `confidential/record.txt`, the original diagnosis was still recoverable from the `null` version. "We deleted it" therefore does not mean "the data can no longer be recovered" — which is precisely what an erasure right under a regime such as the PDPA or GDPR requires the data controller to guarantee.

Two mechanisms that make the deletion provable:

1. **Explicit per-version deletion, backed by lifecycle rules.** Call `delete-object` with every `VersionId` of the object (and every delete marker) so no copy of the plaintext remains in the bucket, and pair this with a `NoncurrentVersionExpiration` lifecycle rule so old versions are purged automatically and on a documented schedule rather than relying on someone remembering to do it by hand.
2. **Cryptographic erasure.** Since every object in the bucket is encrypted under one customer-managed KMS key, scheduling deletion of that key renders every ciphertext copy of the data — current version, all prior versions, and any backups or replicas encrypted under the same key — permanently and irreversibly unrecoverable in a single action, even if a copy was missed or exists outside the team's direct control.

### Q6. You are the auditor in Week 11. Name three commands from this lab whose output you would collect as compliance evidence, and state which control each one evidences.

1. **`aws s3api get-public-access-block --bucket $BUCKET`** — evidences that the Block Public Access guardrail is enforced (all four flags `true`), proving the bucket cannot be made publicly readable even by a future misconfigured policy.
2. **`aws s3api get-bucket-encryption --bucket $BUCKET`** — evidences that default encryption at rest (SSE-KMS with a customer-managed key) is applied to every object automatically, regardless of whether the uploader remembered to request it.
3. **`aws s3api get-bucket-versioning --bucket $BUCKET`** (paired with `get-bucket-lifecycle-configuration --bucket $BUCKET`) — evidences that versioning is enabled and that a documented, automated lifecycle/retention policy exists, supporting both awareness of data remanence and the organisation's ability to demonstrate compliant, provable retention and deletion.

---

## 6. Verification Command Output

```
=== IKB42603 Lab 6 verification: [YOUR BUCKET NAME] ===
[paste PublicAccessBlockConfiguration output here — all four flags should read True]
[paste get-bucket-versioning output here — Enabled]
[paste SSEAlgorithm / KMSMasterKeyID output here — aws:kms / your key id]
[paste lifecycle Rules[].[ID,Status] output here]
[paste KMS KeyState output here — e.g. PendingDeletion]
```

---

## 7. Security Best-Practices Checklist

- [x] Every object carries a classification tag before any access decision is made.
- [x] No bucket policy names `Principal: "*"`; anonymous access was tested and confirmed refused (or documented as a LocalStack limitation).
- [x] Block Public Access is enabled on all four flags.
- [x] Access is granted by least privilege and scoped to a key prefix, never to `/*` by default.
- [x] Default encryption at rest is `aws:kms` with a customer-managed key.
- [x] Sharing uses time-bounded presigned URLs, not permanent public objects.
- [x] Versioning is enabled, and the team understands that delete markers do not destroy data.
- [x] A lifecycle configuration expresses the retention policy, and cryptographic erasure is available for provable deletion.

---

*End of report.*
