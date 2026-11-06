"""A product's Istio ambient mesh policies: mutual TLS everywhere, and calls allowed only where
the product declares them (mirroring workload.yaml dependencies). Enforced by ztunnel at L4 from
each workload's mTLS identity (its service account): nothing reaches a workload because it can
route to it. Cilium keeps its own network policies; don't add Cilium L7 rules for ambient
workloads (the two L7 engines conflict, and Cilium can't see inside the mesh's tunnel).
"""

from __future__ import annotations

from typing import Any

import yaml


def render(spec: dict[str, Any]) -> list[dict[str, Any]]:
    ns = spec["namespace"]
    mesh = spec.get("mesh") or {}
    label = mesh.get("workload_label", "app.kubernetes.io/name")
    sa = mesh.get("service_account", "{name}")
    ingress_ns = mesh.get("ingress_namespace", "openchoreo-data-plane")
    monitoring_ns = mesh.get("monitoring_namespace", "monitoring")
    bff = spec["bff"]["client_id"]

    def principal(name: str) -> str:
        return f"cluster.local/ns/{ns}/sa/{sa.format(name=name)}"

    docs: list[dict[str, Any]] = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": ns, "labels": {"istio.io/dataplane-mode": "ambient"}},
        },
        # Plain-text traffic is refused: every connection is mutually authenticated.
        {
            "apiVersion": "security.istio.io/v1",
            "kind": "PeerAuthentication",
            "metadata": {"name": "strict-mtls", "namespace": ns},
            "spec": {"mtls": {"mode": "STRICT"}},
        },
        # Deny by default: an ALLOW policy with no rules allows nothing; the policies below add exactly
        # the declared calls.
        {
            "apiVersion": "security.istio.io/v1",
            "kind": "AuthorizationPolicy",
            "metadata": {"name": "allow-nothing", "namespace": ns},
            "spec": {},
        },
        # The internet reaches only the BFF, through the platform's gateway.
        allow(ns, f"ingress-to-{bff}", label, bff, [8080], namespaces=[ingress_ns]),
        # The platform's probes and Prometheus reach only the management port.
        {
            "apiVersion": "security.istio.io/v1",
            "kind": "AuthorizationPolicy",
            "metadata": {"name": "monitoring-to-management", "namespace": ns},
            "spec": {
                "action": "ALLOW",
                "rules": [
                    {"from": [{"source": {"namespaces": [monitoring_ns]}}], "to": [{"operation": {"ports": ["8081"]}}]}
                ],
            },
        },
    ]
    for c in spec.get("calls") or []:
        docs.append(
            allow(ns, f"{c['from']}-to-{c['to']}", label, c["to"], [c["port"]], principals=[principal(c["from"])])
        )
    return docs


def allow(
    ns: str,
    name: str,
    label: str,
    to: str,
    ports: list[int],
    *,
    principals: list[str] | None = None,
    namespaces: list[str] | None = None,
) -> dict[str, Any]:
    source: dict[str, Any] = {}
    if principals:
        source["principals"] = principals
    if namespaces:
        source["namespaces"] = namespaces
    return {
        "apiVersion": "security.istio.io/v1",
        "kind": "AuthorizationPolicy",
        "metadata": {"name": name, "namespace": ns},
        "spec": {
            "selector": {"matchLabels": {label: to}},
            "action": "ALLOW",
            "rules": [{"from": [{"source": source}], "to": [{"operation": {"ports": [str(p) for p in ports]}}]}],
        },
    }


def dump(docs: list[dict[str, Any]]) -> str:
    return yaml.safe_dump_all(docs, sort_keys=False)
