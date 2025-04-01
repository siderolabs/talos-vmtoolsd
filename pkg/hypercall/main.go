// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// Package hypercall provides the hypercall between guest and ESXi
// it has been inspired by a lot of sources:
//
// - https://github.com/vmware-archive/vmw-guestinfo
// - https://github.com/vmware/open-vm-tools/
// - https://wiki.osdev.org/VMware_tools
// - https://sysprogs.com/legacy/articles/kdvmware/guestrpc.shtml
// - https://web.archive.org/web/20100610223425/http://chitchat.at.infoseek.co.jp/vmware/backdoor.html
//
// ESX on both Intel and ARM traps a certain instruction (the "backdoor") and
// swaps a set of registers (stackframe). By using special magic values, you
// communicate with the hypervisor.
package hypercall
