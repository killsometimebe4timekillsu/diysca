# NVD API key

diysca uses the [NVD](https://nvd.nist.gov) API for CVSS scores and CVE descriptions. Without a key the NVD allows
about 5 requests per 30 seconds, so scores fill in slowly over several runs. With a key the limit is about 50 requests
per 30 seconds, roughly 10 times faster. The key is free.

## Get a key

1. Open the request form: <https://nvd.nist.gov/developers/request-an-api-key>.
2. Enter your organization name and email address, pick the organization type, accept the terms of use and submit.
3. NVD sends an email with an activation link. Open it within 7 days to activate the key and see it.
4. Copy the key (a UUID like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).

More background: [NVD developer start guide](https://nvd.nist.gov/developers/start-here).

## Configure diysca

In `/etc/diysca/config.yml` (or the config file you pass with `--config`):

```yaml
nvd_api_key: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Or as an environment variable, which is better for OCI containers, Kubernetes secrets and systemd credentials:

```sh
DIYSCA_NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

For the systemd service, put it in a drop-in so it stays out of the config file:

```sh
sudo systemctl edit diysca
# [Service]
# Environment=DIYSCA_NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
sudo systemctl restart diysca
```

Restart diysca after changing the key. Keep the config file readable only by the diysca user
(`chmod 600 /etc/diysca/config.yml`).

## Check that it works

After the next scan, *Recent events* on the dashboard shows a line like `NVD: 120 CVEs enriched, 0 still pending`. Without a key that line ends with a hint that a key makes
it faster. With a key each enrichment run may take up to 600 s instead of 90 s (`nvd_budget_seconds`).

If NVD answers 403 the key is wrong or not activated yet; diysca then stops for this run and tries again next time.
