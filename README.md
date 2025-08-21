# talos-vmtoolsd

## A VMware tools implementation for the Talos Kubernetes platform, using govmomi and Talos' apid

[Talos](https://talos.dev/) ships as OVA file for VMware platforms, but by design lacks first-party hypervisor integration packages.
Restart/stop buttons for Talos nodes will not function and VM details are not available in vCenter.

Deploying this program on your Talos cluster provides native integration of Talos with vSphere/vCenter.

## Installation as a Talos System Extension

The preferred use is as a [System Extension](https://www.talos.dev/latest/talos-guides/configuration/system-extensions/).
Please refer to the Talos documentation on how to build [Boot Assets](https://www.talos.dev/latest/talos-guides/install/boot-assets/#imager)
that include `talos-vmtoolsd`.

Basically, for a node upgrade, it boils down to something like this:

```bash
# Generate installer image including `talos-vmtoolsd`
docker run --rm --tty \
    --volume $PWD/_out:/out ghcr.io/siderolabs/imager:<talos version> \
    installer \
    --system-extension-image ghcr.io/siderolabs/talos-vmtoolsd:<talos vmtoolsd version>

# Push the installer image as a container to your registry
crane push _out/installer-amd64.tar ghcr.io/<username></username>/talos-installer:<talos version>

# Upgrade node
talosctl upgrade --nodes <node ip> \
    --image ghcr.io/<username></username>/talos-installer:<talos version>
```

## Installation as a DaemonSet

Start by providing authorization credentials to enable talos-vmtoolsd to talk with apid.
Admin credentials are required in order to issue reboot/shutdown commands.

```bash
# Create new Talos API credentials
talosctl --nodes <node ip> config new vmtoolsd-secret.yaml --roles os:admin

# Import API credentials into K8s
kubectl --namespace kube-system \
    create secret generic talos-vmtoolsd-config \
    --from-file=talosconfig=./vmtoolsd-secret.yaml

# Delete temporary credentials file
rm vmtoolsd-secret.yaml
```

If you craft your own manifests, please remember the note about `GRPC_ENFORCE_ALPN_ENABLED=false` below.

Install or upgrade `talos-vmtoolsd`:

```bash
kubectl apply --filename https://raw.githubusercontent.com/siderolabs/talos-vmtoolsd/master/deploy/latest.yaml
```

The `CAP_SYS_RAWIO` capability is used to perform a check to determine whether the environment is VMware.
This check can be skipped by setting env var `VMTOOLSD_SKIP_VMWARE_DETECTION=true`.
Note that `Segmentation fault` will be produced if the environment is **not** VMware.

## Talos Compatibility Matrix

Please find an [older version of this matrix](https://github.com/siderolabs/talos-vmtoolsd/blob/0.4.0/README.md)
for compatibility with older Talos and vmtoolsd-verions.

| ⬇️ Tools \ Talos ➡️ |  1.5 | 1.6 | 1.7 | 1.8 | 1.9 |
| ------------------ | --- | ----| --- | ---- | --- |
| **1.0** (current)  |  ⚠️   |  ⚠️  |  ⚠️  |  ⚠️  | ✅  |
| **0.6**            |  ✅  | ✅  | ✅  | ✅  | ⚠️  |
| **0.5**            |  ✅  | ✅  |     |     |    |

Talos 1.8+ carries gRPC >= 1.67, which [has issues with older gRPC](https://github.com/siderolabs/talos/issues/9463),
and causes gRPC errors like these:

```text
rpc error: code = Unavailable desc = connection error: desc = \"transport: authentication handshake failed: credentials: cannot check peer: missing selected ALPN property\"
```

There are two workarounds:

1. use older (< 0.7) `talos-vmtoolsd` on older (< 1.9) Talos versions
2. set `GRPC_ENFORCE_ALPN_ENABLED=false` and everything will be fine

The latter option is used in the system extention and example manifests.

## Roadmap

* [x] Feature-complete integration of Talos apid and ESXi (restart/stop, IP, DNS, heartbeats)
* [x] Continuous Integration & Deployment via GitHub Actions
* [x] Validate interopability with with VMware K8s CNI/CSI
* [ ] Warn about unsafe VM config (Talos config accessible to all pods)
* [ ] Unit testing beyond govmomi-provided tests

## Why not open-vm-tools?

The standard open-vm-tools package in a container has multiple shortcomings under Talos:

1. It wants a shutdown binary, but there is none that works properly with Talos.
2. Its out-of-band process and file management goes against Talos' immutability principle.
3. Exposing virtual network adapters to vSphere can cause issues like described in the
   [VMware CPI documentation](https://cloud-provider-vsphere.sigs.k8s.io/known_issues.html).
   No workarounds are necessary for talos-vmtoolsd.

The standard open-vm-tools package expects to run on the host and have some program (e.g. `/usr/bin/shutdown`) to handle shutdown requests.
Running open-vm-tools in a privileged container may work, but it provides mediocre results with Talos.
For example, I have observed shutdown commands from containers to bypass apid and be either ignored or lead to unclean termination of pods.

Talos' apid may be used to talk to local services by omitting a node context.
This feature is not supported by talosctl.
Incidentally, VMware provides a guest tools implementation in Go as part of the govmomi project.
Combining both, talos-vmtoolsd was born: A single lightweight process that can talk to both ESXi and Talos' apid.
It simply translates between both interfaces and thereby seamlessly integrates them.

## Attribution

This tool was originally written by Oliver Kuckertz, and was adopted by Equinix and Siderolabs.
Talos-vmtoolsd is based on VMware's custom VIC toolbox of the govmomi project.
I have reduced the toolbox's functionality to the bare minimum required by vSphere.
Its main service has been refactored for plugin support.
A basic plugin is provided serve requests from vSphere using Talos' apid.
Code to access apid is imported from Talos' official toolchain and shared by e.g. talosctl.

## License

This program is licensed under the Apache 2.0 license like its dependency govmomi.
