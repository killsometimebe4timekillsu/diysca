# Inventory providers

Besides Ansible inventories, diysca reads systems straight from hypervisors, clouds and clusters. Providers are
configured in `config.yml` under `inventory_providers`, and are read at start, before every scheduled scan,
with *Settings > Inventory > Import now* and with `diysca import`. *Settings > Inventory* shows each source,
how many systems it found and the last error.

Systems are still scanned over SSH: the provider only tells diysca which systems exist and their address.
Every system gets the groups `<type>` and `<name>` of its provider plus the provider's own (tags, node, zone),
so alert subscriptions, role scopes and scan selections can use `group:proxmox`, `group:pve`, ...

## Options every provider takes

| Option | Meaning |
|---|---|
| `name` | label and group name (default: the type) |
| `user`, `port`, `key_file` | SSH login for the systems found |
| `address` | `ip` (default) or `name` (scan by DNS / VM name) |
| `groups` | extra groups for every system |
| `include`, `exclude` | name patterns, comma separated |
| `running_only` | skip stopped VMs (default true) |
| `verify_tls` | true, false or a CA bundle path |
| `enabled` | false to keep the entry but not read it |

Secrets: every secret option `x` also works as `x_env` (environment variable) and `x_file` (file).

## Proxmox VE

```yaml
- {type: proxmox, name: pve, url: https://pve1:8006, token_id: "diysca@pve!scan", token_secret_env: PVE_TOKEN,
   nodes: true, user: root}
```

QEMU VMs and LXC containers from `/cluster/resources`. IPs from the QEMU guest agent and the LXC interfaces.
`nodes: true` also adds the PVE nodes. An API token with the PVEAuditor role is enough (VM.Monitor for the
guest agent). Windows VMs (ostype win*) go into the `windows` group.

## VMware vSphere

```yaml
- {type: vsphere, name: vc, url: https://vcenter.example.org, username: ro@vsphere.local, password_env: VC_PW}
```

Powered-on VMs through the vSphere Automation REST API (vCenter 7.0U2 and newer). IP and OS family from
VMware Tools. A read-only role is enough.

## KVM / libvirt

```yaml
- {type: libvirt, name: kvm, uris: ["qemu+ssh://root@kvm1/system", "qemu+ssh://root@kvm2/system"], hypervisor: true}
```

Running domains with `virsh`. Addresses from the DHCP lease, the guest agent, then ARP. `hypervisor: true`
also adds the KVM hosts. Needs the libvirt client (`virsh`) where diysca runs; in the OCI image, mount an SSH
key the libvirt hosts accept.

## OpenStack

```yaml
- {type: openstack, name: cloud, auth_url: https://keystone:5000/v3, region: RegionOne,
   application_credential_id: "...", application_credential_secret_env: OS_APP_SECRET}
```

ACTIVE Nova servers of the project. Password auth works too (`username`, `password_env`, `project_name`,
`user_domain_name`, `project_domain_name`). Address: floating IP, else the first fixed IPv4 (`network:` picks
a network). Server metadata `groups=a,b` becomes groups.

## Kubernetes and OpenShift

```yaml
- {type: kubernetes, name: prod, url: https://k8s-api:6443, token_env: K8S_TOKEN, ca_file: /etc/diysca/k8s-ca.pem}
- {type: openshift, name: ocp, kubeconfig: /etc/diysca/kubeconfig, context: ocp, user: core}
```

Ready nodes, with their InternalIP (`address: external` for the ExternalIP), node roles and zone as groups.
The token needs get / list on nodes. diysca then scans each node's OS and, with `scan_containers: true`, the
running pod containers on it through `crictl` (one per image); set `container_sudo: true`. OpenShift nodes run
RHCOS: SSH in as `core`.

## AWS EC2

```yaml
- {type: aws, name: aws-eu, regions: [eu-central-1, eu-west-1], access_key_id_env: AWS_ACCESS_KEY_ID,
   secret_access_key_env: AWS_SECRET_ACCESS_KEY, address: private, filters: {"tag:env": prod}}
```

Running instances, signed with SigV4 (no SDK needed). The Name tag is the system name, other tags become
`tag_<key>_<value>` groups. IAM: `ec2:DescribeInstances`.

## Microsoft Azure

```yaml
- {type: azure, name: az, tenant_id: "...", client_id: "...", client_secret_env: AZURE_CLIENT_SECRET,
   subscriptions: [], address: private}
- {type: azure, name: az, managed_identity: true}     # diysca runs on an Azure VM, AKS or Container Apps
```

Running VMs of every subscription the identity can read (or the listed ones), with one Azure Resource Graph
query that also resolves NIC and public IP addresses. Role: Reader. Groups: `rg_<resource group>`,
`region_<location>`, `tag_<key>_<value>`. `resource_groups:` limits it.

## Google Cloud

```yaml
- {type: gcp, name: gcp, projects: [prod-123, shared-456], credentials_file: /etc/diysca/gcp-sa.json}
- {type: gcp, name: gcp, projects: [prod-123]}         # on GCE / GKE: the metadata server's service account
```

Running Compute Engine instances of the projects (aggregated list, every zone). The service account needs
`roles/compute.viewer`. Groups: `project_<id>`, `zone_<zone>`, `label_<key>_<value>`, `tag_<network tag>`.
`filter:` takes the Compute API filter syntax (`labels.env=prod`). Windows images go into `windows`.

## Hetzner Cloud

```yaml
- {type: hetzner, name: hcloud, token_env: HCLOUD_TOKEN, label_selector: "env=prod"}
```

Running servers of the project. Address: the public IPv4, or with `address: private` the private network
address (`network:` picks one). Groups: `location_<fsn1>`, the OS flavor, `label_<key>_<value>`. A read-only
API token is enough.

## Other clouds

DigitalOcean, OVHcloud, Scaleway, Linode and others: put their Ansible inventory plugin file under
`inventories:`; diysca reads it with `ansible-inventory`.

## Windows hosts

Windows systems from any provider land in the `windows` group (or put them there in your Ansible inventory).
diysca reaches them through OpenSSH Server (built into Windows Server 2019+ and Windows 10/11; WinRM-only hosts
are tried on port 22) and records the edition, build, installed updates (KBs) and installed programs.

Not done yet: matching that against Microsoft's security update guide (MSRC). OSV has no Windows data, so a
Windows system shows its inventory and a note instead of findings.
