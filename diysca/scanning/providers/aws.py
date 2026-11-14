"""AWS EC2: running instances of one or more regions (DescribeInstances, signed with SigV4, no SDK needed).

    - type: aws
      regions: [eu-central-1, eu-west-1]
      access_key_id_env: AWS_ACCESS_KEY_ID
      secret_access_key_env: AWS_SECRET_ACCESS_KEY
      session_token_env: AWS_SESSION_TOKEN   # optional
      address: private                        # private (default) | public | name (private DNS name)
      filters: {"tag:env": prod}

IAM: ec2:DescribeInstances is enough. The Name tag is the system name, the other tags become groups
(tag_<key>_<value>, like the Ansible aws_ec2 plugin).
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import xml.etree.ElementTree as ET
from urllib.parse import quote

from diysca.scanning.providers import ProviderError, check, host, http, secret, split

NS = "{http://ec2.amazonaws.com/doc/2016-11-15/}"


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def signed_headers(method: str, hostname: str, region: str, query: str, akid: str, secret_key: str,
                   token: str = "", now: datetime.datetime | None = None) -> dict:
    """AWS Signature Version 4 for a GET with an empty body."""
    now = now or datetime.datetime.now(datetime.UTC)
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    hdrs = {"host": hostname, "x-amz-date": amz}
    if token:
        hdrs["x-amz-security-token"] = token
    names = ";".join(sorted(hdrs))
    canon = "\n".join([method, "/", query, "".join(f"{k}:{hdrs[k]}\n" for k in sorted(hdrs)), names,
                       hashlib.sha256(b"").hexdigest()])
    scope = f"{day}/{region}/ec2/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canon.encode()).hexdigest()])
    k = _sign(_sign(_sign(_sign(("AWS4" + secret_key).encode(), day), region), "ec2"), "aws4_request")
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    hdrs["authorization"] = f"AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders={names}, Signature={sig}"
    return hdrs


def _query(params: dict) -> str:
    return "&".join(f"{quote(k, safe='-_.~')}={quote(str(v), safe='-_.~')}" for k, v in sorted(params.items()))


def _text(el, path):
    x = el.find(path)
    return x.text if x is not None else None


def discover(cfg: dict, transport=None):
    regions = split(cfg.get("regions") or cfg.get("region") or "")
    if not regions:
        raise ProviderError("aws needs regions")
    akid, sk = secret(cfg, "access_key_id"), secret(cfg, "secret_access_key")
    if not akid or not sk:
        raise ProviderError("aws needs access_key_id and secret_access_key (or their _env variants)")
    token = secret(cfg, "session_token")
    out = []
    with http(cfg, transport) as c:
        for region in regions:
            hostname = f"ec2.{region}.amazonaws.com"
            base = {"Action": "DescribeInstances", "Version": "2016-11-15", "MaxResults": 500}
            filters = dict(cfg.get("filters") or {})
            if cfg.get("running_only", True):
                filters["instance-state-name"] = "running"
            for i, (k, v) in enumerate(filters.items(), 1):
                base[f"Filter.{i}.Name"] = k
                for j, val in enumerate(split(v), 1):
                    base[f"Filter.{i}.Value.{j}"] = val
            next_token = None
            while True:
                q = _query({**base, **({"NextToken": next_token} if next_token else {})})
                r = check(c.get(f"https://{hostname}/?{q}",
                                headers=signed_headers("GET", hostname, region, q, akid, sk, token)),
                          f"aws {region} DescribeInstances")
                root = ET.fromstring(r.text)
                for inst in root.iter(NS + "instancesSet"):
                    for it in inst.findall(NS + "item"):
                        tags = {_text(t, NS + "key"): _text(t, NS + "value") or ""
                                for t in it.findall(f"{NS}tagSet/{NS}item")}
                        iid = _text(it, NS + "instanceId")
                        priv, pub = _text(it, NS + "privateIpAddress"), _text(it, NS + "ipAddress")
                        want = cfg.get("address", "private")
                        ip = pub if want == "public" else priv
                        name = tags.get("Name") or iid
                        if want == "name":
                            name, ip = _text(it, NS + "privateDnsName") or name, None
                        platform = "windows" if (_text(it, NS + "platform") or "").lower() == "windows" else ""
                        groups = [f"aws_{region}", f"az_{_text(it, f'{NS}placement/{NS}availabilityZone') or ''}"] + \
                            [f"tag_{k}_{v}" for k, v in tags.items() if k != "Name" and not k.startswith("aws:")]
                        out.append(host(cfg, name, ip, groups, platform, ec2_instance_id=iid))
                next_token = _text(root, NS + "nextToken")
                if not next_token:
                    break
    return out
