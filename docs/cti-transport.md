# CTI Transport: STIX, TAXII, and Sigma

PhishAnalyze can export STIX 2.1 and Sigma content for security operators.
File export remains the default. TAXII push is optional and disabled unless
explicitly configured.

## STIX to TAXII

Use `scripts/taxii_push.py` to push STIX bundle objects into a TAXII 2.1
collection:

```bash
python scripts/taxii_push.py \
  --stix data/exports/example_iocs.json \
  --base-url https://taxii.example/api1 \
  --collection-id example-collection
```

The client sends a TAXII Add Objects envelope:

```json
{"objects": ["STIX objects from the bundle"]}
```

It does not send the STIX bundle wrapper itself. Status is written to
`data/taxii_push_status.json` by default so the private admin overview can show
success, failure, timeout, object count, HTTP status, and duration without
exposing credentials or bundle contents.

Environment variables:

- `TAXII_PUSH_ENABLED`
- `TAXII_BASE_URL`
- `TAXII_COLLECTION_ID`
- `TAXII_OBJECTS_URL`
- `TAXII_USERNAME`
- `TAXII_PASSWORD`
- `TAXII_BEARER_TOKEN`
- `TAXII_TIMEOUT_SECONDS`
- `TAXII_VERIFY_TLS`
- `TAXII_STATUS_PATH`

Prefer `TAXII_OBJECTS_URL` when a provider uses a non-standard API root. The
status file strips query strings and embedded credentials from the target URL.

## Private OpenCTI Deployment

For a co-located OpenCTI stack, keep OpenCTI off the public tunnel and expose it
only on a private Docker network. Configure APD with the service DNS name from
that network:

```bash
TAXII_PUSH_ENABLED=true
TAXII_OBJECTS_URL=http://opencti:8080/taxii2/root/collections/<collection-id>/objects/
TAXII_BEARER_TOKEN=<service-account-token>
TAXII_VERIFY_TLS=false
CTI_DOCKER_NETWORK=opencti_internal
CTI_DOCKER_NETWORK_REQUIRED=1
```

`scripts/docker_deploy.sh` reconnects the app container to
`CTI_DOCKER_NETWORK` after each redeploy. Use a dedicated OpenCTI service
account with `TAXIIAPI` access instead of the administrator token. Keep the
OpenCTI UI behind SSH or a Cloudflare Access-protected hostname if it ever needs
browser access.

## Sigma Conversion CI

Structural Sigma validation still runs through the signed export validator.
CI also installs pySigma and the Splunk backend in a separate job:

```bash
python scripts/sigma_convert_check.py --backend splunk --require-converter
```

This catches rules that look valid as YAML but cannot be converted by a real
downstream backend. The status file is `data/sigma_conversion_status.json`.

## Admin Visibility

The `/admin` overview shows:

- TAXII enabled/configured state
- last TAXII push status and object count
- Sigma converter status
- converted rule count and failure count

The admin payload is aggregate operational state only. It does not include STIX
objects, Sigma query text, raw email bodies, API keys, bearer tokens, or TAXII
passwords.
