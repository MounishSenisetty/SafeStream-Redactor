# Annotation guidelines: real-world redaction corpus

Mark every value that **must not leave the organisation** if this document were
shared with an outside party (a vendor, a public issue tracker). Annotate
independently; do not discuss documents with the other annotator until both of
you have finished and agreement has been measured.

## What to mark, and with which type

| Type | Mark | Examples (all fake) |
|---|---|---|
| `SECRET` | Anything that grants access: API keys, access tokens, passwords, private keys, connection-string passwords, session cookies, webhook URLs with an embedded token | `AKIAIOSFODNN7EXAMPLE`, `ghp_…`, `-----BEGIN RSA PRIVATE KEY-----…` |
| `EMAIL_ADDRESS` | A personal or work e-mail address | `jane.doe@example.com` |
| `PHONE_NUMBER` | A telephone number | `+1 202 555 0143` |
| `CREDIT_CARD` | A payment card number | `4111 1111 1111 1111` |
| `US_SSN` | A US social-security number | `123-45-6789` |
| `IP_ADDRESS` | An IPv4 or IPv6 address of a host or person (not `127.0.0.1` or `0.0.0.0`) | `192.0.2.10` |
| `PERSON` | A person's name, including user handles that are clearly names | `Jane Doe` |
| `LOCATION` | A street address, or a city tied to a person | `12 Example Street` |
| `ORGANIZATION` | A customer's or person's organisation; not the product or the tool itself | |
| `ID` | Account, customer, employee, patient, licence or national identifiers | `Patient ID: 0042137` |
| `USERNAME` | A login name that is not a person's name | `svc_backup` |
| `URL` | A URL that identifies a person or private resource | |
| `DATE_TIME` | Only dates of birth or dates tied to a person's record | |
| `IBAN_CODE`, `CRYPTO`, `MAC_ADDRESS` | Bank account, wallet address, hardware address | |
| `OTHER` | Sensitive and none of the above; say why in your notes | |

For `SECRET`, add a `subtype` when you can name the issuer (`aws_key`,
`github_token`, `private_key`, `password`, `jwt`, `slack_token`, ...). The
subtype lets results be reported per credential type.

## Boundaries

- Mark the **value only**: not the key name, the quotes or the separator. In
  `password="hunter2"`, mark `hunter2`.
- Mark the **whole value**, even if it wraps lines (private keys) or is long.
- A connection string `postgres://admin:s3cret@db.example.com/app` holds a
  `SECRET` (`s3cret`) and possibly a `USERNAME` (`admin`). Mark them as separate
  spans; the host is `URL` only if it identifies a private resource.
- Do not mark placeholders and masks: `${DB_PASSWORD}`, `<token>`, `****`,
  `REDACTED`, `xxx`, or values a tool has already masked.
- Do not mark well-known public values: documentation example keys inside
  documentation, public IP ranges of a cloud provider, version numbers, hashes of
  public artefacts (commit SHAs, image digests) unless a key name says they are
  secret.
- A value that appears several times is marked every time.

## Necessity

`mandatory` (the default): it must be redacted before sharing. Use `contextual`
only for values whose sensitivity depends on who receives the document (for
example an internal host name). Both annotators should use `contextual`
sparingly, and every use is reviewed in adjudication.

## Adjudication

After agreement is measured, a third person (or both annotators together)
resolves each disagreement into `adjudicated.jsonl`. Record the rule applied to
recurring cases, and add it to this file before the corpus is frozen, so the
guidelines and the gold standard stay consistent.
