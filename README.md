# talos-vmtoolsd

**A VMware tools implementation for the Talos Kubernetes platform, using govmomi and Talos' apid**

[Talos](https://talos.dev/) ships as OVA file for VMware platforms, but by design lacks first-party hypervisor integration packages. Restart/stop buttons for Talos nodes will not function and VM details are not available in vCenter.

Deploying this program on your Talos cluster provides native integration of Talos with vSphere/vCenter.

# Installation

A standard K8s DaemonSet is used for deployment.

Start by providing authorization credentials to enable talos-vmtoolsd to talk with apid. Admin credentials are required in order to issue reboot/shutdown commands.

```
# create new Talos API credentials
# (insert a control plane node's IP at $IP)
talosctl -n $IP config new vmtoolsd-secret.yaml --roles os:admin

# import API credentials into K8s
kubectl -n kube-system create secret generic talos-vmtoolsd-config \
  --from-file=talosconfig=./vmtoolsd-secret.yaml

# delete temporary credentials file
rm vmtoolsd-secret.yaml
```

Install or upgrade `talos-vmtoolsd`:

```
kubectl apply -f https://raw.githubusercontent.com/mologie/talos-vmtoolsd/release-0.2/deploy/0.2.yaml
```

# Talos Compatibility Matrix

| ⬇️ Tools \ Talos ➡️ | 0.7 - 0.10 | 0.11 - 0.13 | 0.14+ |
| ----------------- | ---------- | ----------- | ----- |
| **0.3** (current) |  ❌         | ✅          | ✅    |
| **0.2**           |  ✅         | ✅          | ❌    |

# Roadmap

* [x] Feature-complete integration of Talos apid and ESXi (restart/stop, IP, DNS, heartbeats)
* [x] Continuous Integration & Deployment via GitHub Actions
* [x] Validate interopability with with VMware K8s CNI/CSI
* [ ] Warn about unsafe VM config (Talos config accessible to all pods)
* [ ] Unit testing beyond govmomi-provided tests

# Why not open-vm-tools?

The standard open-vm-tools package in a container has multiple shortcomings under Talos:

1. It wants a shutdown binary, but there is none that works properly with Talos.
2. Its out-of-band process and file management goes against Talos' immutability principle.
3. Exposing virtual network adapters to vSphere can cause issues like described in the [VMware CPI documentation](https://cloud-provider-vsphere.sigs.k8s.io/known_issues.html). No workarounds are necessary for talos-vmtoolsd.

The standard open-vm-tools package expects to run on the host and have some program (e.g. `/usr/bin/shutdown`) to handle shutdown requests. Running open-vm-tools in a privileged container may work, but it provides mediocre results with Talos. For example, I have observed shutdown commands from containers to bypass apid and be either ignored or lead to unclean termination of pods.

Talos' apid may be used to talk to local services by omitting a node context. This feature is not supported by talosctl. Incidentally, VMware provides a guest tools implementation in Go as part of the govmomi project. Combining both, talos-vmtoolsd was born: A single lightweight process that can talk to both ESXi and Talos' apid. It simply translates between both interfaces and thereby seamlessly integrates them.

# Attribution

Talos-vmtoolsd is based on VMware's custom VIC toolbox of the govmomi project. I have reduced the toolbox's functionality to the bare minimum required by vSphere. Its main service has been refactored for plugin support. A basic plugin is provided serve requests from vSphere using Talos' apid. Code to access apid is imported from Talos' official toolchain and shared by e.g. talosctl.

# License

This program is licensed under the Apache 2.0 license like its dependency govmomi.
