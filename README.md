# talos-vmtoolsd

HERE BE DRAGONS! This third-party VMware tools implementation is new to this world. It may randomly reboot your cluster when you're looking away. I am reasonably confident that it won't delete your data, though it might eat babies, so please handle it with care. This message will be removed after talos-vmtoolsd was sufficiently tested by the Talos community.

**VMware tools implementation for the Talos Kubernetes platform, using govmomi and Talos' apid**

[Talos](https://talos.dev/) ships as OVA file for VMware platforms, but by design lacks first-party hypervisor integration packages. Start/stop buttons for Talos nodes will not function and VM details are not available in vCenter.

Deploying this program on your Talos environment provides native integration of Talos with vSphere/vCenter.

# Installation

A standard K8s DaemonSet is used for deployment.

Start by providing authorization credentials to enable talos-vmtoolsd to talk with apid. The `talosconfig` file is generated as first step during your Talos cluster setup. Adjust the path if needed.

```
kubectl --namespace kube-system create secret generic talos-vmtoolsd-config \
  --from-file=talosconfig=./talosconfig
```

Install or upgrade `talos-vmtoolsd`:

```
kubectl apply -f https://<TODO: url>
```

# Why not open-vm-tools?

The standard open-vm-tools package expects to run on the host and have some program (e.g. /usr/bin/shutdown) to handle shutdown requests. Running open-vm-tools in a privileged container may work, but it provides mediocre results with Talos. For example, I have observed shutdown commands from containers to bypass apid and be either ignored or lead to unclean termination of pods.

Some glue code would be required to integrate open-vm-tools' shutdown request with Talos' lifecycle controller in machined via apid, similar to how `talosctl shutdown` would work. Indeed, a small script to call `talosctl shutdown -n <current node's IP>` would do the trick, but... it feels wrong, if that makes sense?

Talos' apid may be used to talk to local services by omitting a node context. This feature is not supported by talosctl. Incidentally, VMware provides a guest tools implementation in Go as part of the govmomi project.

Combining both, talos-vmtoolsd was born: A single, lightweight process that can talk to both ESXi and Talos' apid. It simply translates between both interfaces and provides seamless integration.

(It may or may not be a factor that I was bored during Covid-Christmas ;-D.)

# Attribution

Talos-vmtoolsd is based on VMware's custom VIC toolbox of the govmomi project. I have reduced the toolbox's functionality to the bare minimum required by vSphere. Its main service has been refactored for plugin support. A basic plugin is provided serve requests from vSphere using Talos' apid. Code to access apid is imported from Talos' official toolchain and shared by e.g. talosctl.

# License

This program is licensed under the Apache 2.0, a license shared by its dependency govmomi.
