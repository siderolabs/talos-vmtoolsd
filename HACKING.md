# Tips for hacking development

## Query `osUptime` for verification

VMware expects to receive uptime information in 100s of seconds. We want to
make sure it gets what it wants, and for that we must read the vm metric
`sys.osUptime.latest` from vSphere. This is how we do that using
[govc](https://github.com/vmware/govmomi):

```shell
watch ./govc metric.sample vm-276015 sys.osUptime.latest
```