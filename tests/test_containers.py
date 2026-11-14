import asyncio

from diysca import db
from diysca.containers import SEP, ContainerTransport, parse_discovery, sync_container_hosts


def test_parse_discovery_dedups_images():
    out = ("docker\tabc\tweb-1\tnginx:1.25\tsha256:111\n"
           "docker\tdef\tweb-2\tnginx:1.25\tsha256:111\n"
           "podman\tghi\tpg\tdocker.io/library/postgres:16\tsha256:222\n"
           f"{SEP}crictl\n" + '{"containers":[{"id":"jkl","metadata":{"name":"coredns"},"image":{"image":"registry.k8s.io/coredns:v1.11"},"imageRef":"sha256:333"}]}\n')
    got = parse_discovery(out)
    assert [(c["runtime"], c["name"]) for c in got] == [("docker", "web-1"), ("podman", "pg"), ("crictl", "coredns")]


def test_sync_container_hosts():
    hid = db.x("INSERT INTO hosts(name,address,groups) VALUES ('h1','10.0.0.1','prod')")
    parent = db.q1("SELECT * FROM hosts WHERE id=?", (hid,))
    ids = sync_container_hosts(parent, [{"runtime": "podman", "id": "abc", "name": "pg", "image": "postgres:16", "image_id": "x"}])
    child = db.q1("SELECT * FROM hosts WHERE id=?", (ids[0],))
    assert child["name"] == "h1/pg" and child["kind"] == "container" and child["groups"] == "container,prod"
    sync_container_hosts(parent, [])
    assert db.q1("SELECT COUNT(*) n FROM hosts WHERE kind='container'")["n"] == 0


def test_container_transport_wraps_command():
    seen = []

    class P:
        async def run(self, cmd, binary=False, timeout=300):
            seen.append(cmd)
            return "ok"

        async def close(self):
            pass

    t = ContainerTransport(P(), "podman", "abc123")
    assert asyncio.run(t.run("cat /etc/os-release")) == "ok"
    assert seen[0] == "podman exec -u 0 abc123 sh -c 'cat /etc/os-release'"
