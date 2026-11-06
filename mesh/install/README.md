# Istio ambient mode on OpenChoreo's data plane

Istio ambient gives every workload a mutual-TLS identity (its service account) without sidecars:
`ztunnel` on each node encrypts and authenticates pod-to-pod traffic and enforces L4 authorization
policies. Waypoint proxies (optional, per namespace) add L7 policy when a product needs it.

OpenChoreo's data plane uses Cilium. Both run together with two Cilium settings
(`cilium-values.yaml`):

- `cni.exclusive: false`: Cilium leaves room for Istio's CNI plugin.
- `socketLB.hostNamespaceOnly: true`: Cilium's socket load balancing doesn't bypass ztunnel.

Then install Istio with the ambient profile (`istio-ambient-values.yaml`):

```bash
helm upgrade cilium cilium/cilium -n kube-system --reuse-values -f cilium-values.yaml
helm install istio-base istio/base -n istio-system --create-namespace
helm install istiod istio/istiod -n istio-system -f istio-ambient-values.yaml
helm install istio-cni istio/cni -n istio-system --set profile=ambient
helm install ztunnel istio/ztunnel -n istio-system
```

Rules for living with both:

- **Istio** enforces who may call whom between mesh workloads (`mesh/policies/`, generated per
  product): mTLS STRICT, deny by default, allow only the declared calls.
- **Cilium** keeps OpenChoreo's network policies (L3/L4 cell isolation, egress). Don't add Cilium
  L7 (HTTP) policies for ambient workloads: Cilium can't see inside the mesh's tunnel, and two L7
  engines disagree.
- Prometheus and the platform's probes reach only port 8081 (management) of each workload.

Check the versions against your OpenChoreo release before upgrading either.
