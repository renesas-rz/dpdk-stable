.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2023 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 23.11
==================

New Features
------------

* **Build requirements increased for C11.**

  From DPDK 23.11 onwards,
  building DPDK will require a C compiler which supports the C11 standard,
  including support for C11 standard atomics.

  More specifically, the requirements will be:

  * Support for flag ``-std=c11`` (or similar)
  * ``__STDC_NO_ATOMICS__`` is *not defined* when using c11 flag

  Please note:

  * C11, including standard atomics, is supported from GCC version 5 onwards,
    and is the default language version in that release
    (Ref: https://gcc.gnu.org/gcc-5/changes.html)
  * C11 is the default compilation mode in Clang from version 3.6,
    which also added support for standard atomics
    (Ref: https://releases.llvm.org/3.6.0/tools/clang/docs/ReleaseNotes.html)

* **Updated dependencies when linking against libarchive.**

  When the libarchive development package is present on the system,
  DPDK will use libarchive and register a dependency on it.
  However, on a number of Linux distributions, including, for example, Fedora and Ubuntu,
  installing the libarchive dev package does not cause all required dependencies for static linking to be automatically installed too.
  These additional dev packages, such as ``liblz4-dev`` and ``libacl1-dev`` on Ubuntu,
  will need to be installed manually (if not already present)
  to prevent errors with linking against DPDK static libraries.

* **Added new build options.**

  * Enabling deprecated libraries is now done using
    the new ``enable_deprecated_libraries`` build option.
  * Optional libraries can now be selected with the new ``enable_libs``
    build option similarly to the existing ``enable_drivers`` build option.

* **Introduced a new API for atomic operations.**

  This new API serves as a wrapper for transitioning
  to standard atomic operations as described in the C11 standard.
  This API implementation points at the compiler intrinsics by default.
  The implementation using C11 standard atomic operations is enabled
  via the ``enable_stdatomic`` build option.

* **Added support for power intrinsics with AMD processors.**

  Added AMD ``MONITORX``/``MWAITX`` instructions in EAL for power optimisation.

* **Added support for allow/block list in vmbus bus driver.***

  The ``vmbus`` bus driver now supports ``-a`` and ``-b`` EAL options
  for selecting devices.

* **Added mbuf recycling support.**

  Added ``rte_eth_recycle_rx_queue_info_get`` and ``rte_eth_recycle_mbufs``
  functions which allow the user to copy used mbufs from the Tx mbuf ring
  into the Rx mbuf ring. This feature supports the case that the Rx Ethernet
  device is different from the Tx Ethernet device with respective driver
  callback functions in ``rte_eth_recycle_mbufs``.

* **Added amd-pstate driver support to the power management library.**

  Added support for amd-pstate driver which works on AMD EPYC processors.

* **Added maximum Rx buffer size to report.**

  Introduced the ``max_rx_bufsize`` field, representing
  the maximum Rx buffer size per descriptor supported by the HW,
  in the structure ``rte_eth_dev_info`` to avoid wasting mempool space.

* **Improved support of RSS hash algorithm.**

  * Added support to query RSS hash algorithm capability via ``rte_eth_dev_info_get()``,
    and set RSS hash algorithm via ``rte_eth_dev_configure()``
    or ``rte_eth_dev_rss_hash_update()``.

  * Added new function ``rte_eth_dev_rss_algo_name``
    to get name of RSS hash algorithm.

* **Added packet type flow matching criteria.**

  Added ``RTE_FLOW_ITEM_TYPE_PTYPE`` to allow matching on L2/L3/L4
  and tunnel information as defined in mbuf packet type.

* **Added a flow action type for P4-defined actions.**

  For P4-programmable devices, hardware pipeline can be configured through
  a new "PROG" action type and its associated custom arguments.
  Such P4 pipelines, not using the standard blocks of the flow API,
  can be managed with ``RTE_FLOW_ITEM_TYPE_FLEX`` and ``RTE_FLOW_ACTION_TYPE_PROG``.

* **Added flow group set miss actions.**

  Introduced ``rte_flow_group_set_miss_actions()`` API to explicitly set
  a group's miss actions, which are the actions to be performed on packets
  that didn't match any of the flow rules in the group.

* **Updated Amazon ena (Elastic Network Adapter) net driver.**

  * Upgraded ENA HAL to latest version.
  * Added support for connection tracking allowance utilization metrics.
  * Added support for reporting Rx overrun errors in xstats.
  * Added support for ENA-express metrics.

* **Added a new vDPA PMD for Corigine NFP devices.**

  Added a new Corigine NFP vDPA (``nfp_vdpa``) PMD.
  See the :doc:`../vdpadevs/nfp` guide for more details on this driver.

* **Updated Corigine/Netronome nfp driver.**

  * Added inline IPsec offload based on the security framework.

* **Updated Intel cpfl driver.**

  * Added support for port representor.
  * Added support for flow offload (including P4-defined pipeline).

* **Updated Intel iavf driver.**

  * Added support for iavf auto-reset.

* **Updated Intel i40e driver.**

  * Added support for new X722 devices.

* **Updated Marvell cnxk net driver.**

  * Added support for ``RTE_FLOW_ITEM_TYPE_IPV6_ROUTING_EXT`` flow item.
  * Added support for ``RTE_FLOW_ACTION_TYPE_AGE`` flow action.

* **Updated NVIDIA mlx5 net driver.**

  * Added support for multi-port E-Switch.
  * Added support for Network Service Header (NSH) flow matching.
  * Added support for ``RTE_FLOW_ITEM_TYPE_PTYPE`` flow item.
  * Added support for ``RTE_FLOW_ACTION_TYPE_IPV6_EXT_PUSH`` flow action.
  * Added support for ``RTE_FLOW_ACTION_TYPE_IPV6_EXT_REMOVE`` flow action.
  * Added support for ``RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR`` flow action and mirror.
  * Added support for ``RTE_FLOW_ACTION_TYPE_INDIRECT_LIST`` flow action.

* **Updated Solarflare net driver.**

  * Added support for transfer flow action ``INDIRECT`` with subtype ``VXLAN_ENCAP``.
  * Supported packet replay (multi-count / multi-delivery) in transfer flows.

* **Updated Wangxun ngbe driver.**

  * Added 100M and auto-neg support in YT PHY fiber mode.

* **Added support for TLS and DTLS record processing.**

  Added TLS and DTLS record transform for security session
  and added enhancements to ``rte_crypto_op`` fields
  to handle all datapath requirements of TLS and DTLS.
  The support was added for TLS 1.2, TLS 1.3 and DTLS 1.2.

* **Added out of place processing support for inline ingress security session.**

  Similar to out of place processing support for lookaside security session,
  added the same support for inline ingress security session.

* **Added security Rx inject API.**

  Added Rx inject API to allow applications to submit packets
  for protocol offload and have them injected back to ethdev Rx
  so that further ethdev Rx actions (IP reassembly, packet parsing and flow lookups)
  can happen based on the inner packet.

  When using the API implemented by an ethdev the application would be able to process
  packets that are received without/failed inline offload processing
  (such as fragmented ESP packets with inline IPsec offload).
  When using the API implemented by a cryptodev it can be used for injecting packets
  to ethdev Rx after IPsec processing and take advantage of ethdev Rx actions
  for the inner packet which cannot be accelerated in inline protocol offload mode.

* **Updated cryptodev scheduler driver.**

  * Added support for DOCSIS security protocol
    through the ``rte_security`` API callbacks.

* **Updated ipsec_mb crypto driver.**

  * Added Intel IPsec MB v1.5 library support for x86 platform.
  * Added support for digest encrypted to the AESNI_MB asynchronous crypto driver.

* **Updated Intel QuickAssist Technology driver.**

  * Enabled support for QAT 2.0c (4944) devices in QAT crypto driver.
  * Added support for SM2 ECDSA algorithm.

* **Updated Marvell cnxk crypto driver.**

  * Added SM2 algorithm support in asymmetric crypto operations.
  * Added asymmetric crypto ECDH support.

* **Updated Marvell Nitrox symmetric crypto driver.**

  * Added support for AES-CCM algorithm.

* **Updated Intel vRAN Boost baseband driver.**

  * Added support for the new Intel vRAN Boost v2 device variant (GNR-D)
    within the unified driver.

* **Added support for models with multiple I/O in mldev library.**

  Added support in mldev library for models with multiple inputs and outputs.

* **Updated Marvell cnxk mldev driver.**

  * Added support for models compiled using TVM framework.

* **Added new eventdev Ethernet Rx adapter create API.**

  Added new function ``rte_event_eth_rx_adapter_create_ext_with_params()``
  for creating Rx adapter instance for the applications desire to
  control both the event port allocation and event buffer size.

* **Added eventdev DMA adapter.**

  * Added the Event DMA Adapter Library. This library extends the event-based
    model by introducing APIs that allow applications to enqueue/dequeue DMA
    operations to/from dmadev as events scheduled by an event device.

* **Added eventdev support to link queues to port with link profile.**

  Introduced event link profiles that can be used to associate links between
  event queues and an event port with a unique identifier termed the "link profile".
  The profile can be used to switch between the associated links in fast-path
  without the additional overhead of linking/unlinking and waiting for unlinking.

  * Added ``rte_event_port_profile_links_set``, ``rte_event_port_profile_unlink``
    ``rte_event_port_profile_links_get`` and ``rte_event_port_profile_switch``
    functions to enable this feature.

* **Updated Marvell cnxk eventdev driver.**

  * Added support for ``remaining_ticks_get`` timer adapter PMD callback
    to get the remaining ticks to expire for a given event timer.
  * Added link profiles support, up to two link profiles are supported.

* **Updated Marvell cnxk dmadev driver.**

  * Added support for source buffer auto free for memory to device DMA.

* **Added dispatcher library.**

  Added dispatcher library which purpose is to help decouple different
  parts (modules) of an eventdev-based application.

* **Added CLI based graph application.**

  Added CLI based graph application which exercises different use cases.
  The application provides a framework so that each use case can be added via a file.
  Each CLI will further be translated into a graph representing the use case.

* **Added layer 2 MACsec forwarding example application.**

  Added a new example layer 2 forwarding application to benchmark
  MACsec encryption/decryption using rte_security based inline sessions.


Removed Items
-------------

* eal: Removed deprecated ``RTE_FUNC_PTR_OR_*`` macros.

* ethdev: Removed deprecated macro ``RTE_ETH_DEV_BONDED_SLAVE``.

* flow_classify: Removed flow classification library and examples.

* kni: Removed the Kernel Network Interface (KNI) library and driver.

* cryptodev: Removed the arrays of algorithm strings ``rte_crypto_cipher_algorithm_strings``,
  ``rte_crypto_auth_algorithm_strings``, ``rte_crypto_aead_algorithm_strings`` and
  ``rte_crypto_asym_xform_strings``.

* cryptodev: Removed explicit SM2 xform parameter in asymmetric xform.

* security: Removed deprecated field ``reserved_opts``
  from struct ``rte_security_ipsec_sa_options``.

* mldev: Removed functions ``rte_ml_io_input_size_get`` and ``rte_ml_io_output_size_get``.

* cmdline: Removed broken and unused function ``cmdline_poll``.


API Changes
-----------

* eal: The thread API has changed.
  The function ``rte_thread_create_control()`` does not take attributes anymore.
  The whole thread API was promoted to stable level,
  except ``rte_thread_setname()`` and ``rte_ctrl_thread_create()`` which are
  replaced with ``rte_thread_set_name()`` and ``rte_thread_create_control()``.

* eal: Removed ``RTE_CPUFLAG_NUMFLAGS`` to avoid misusage and theoretical ABI
  compatibility issue when adding new cpuflags.

* power: Updated the x86 Uncore power management API so that it is vendor agnostic.

* ethdev: When ``rte_eth_dev_configure`` or ``rte_eth_dev_rss_hash_update`` are called,
  the ``rss_key_len`` of structure ``rte_eth_rss_conf`` should be provided
  by the user for the case ``rss_key != NULL``,
  it won't be taken as default 40 bytes anymore.

* bonding: Replaced master/slave to main/member. The data structure
  ``struct rte_eth_bond_8023ad_slave_info`` was renamed to
  ``struct rte_eth_bond_8023ad_member_info`` in DPDK 23.11.
  The following functions were removed in DPDK 23.11.
  The old functions:
  ``rte_eth_bond_8023ad_slave_info``,
  ``rte_eth_bond_active_slaves_get``,
  ``rte_eth_bond_slave_add``,
  ``rte_eth_bond_slave_remove``, and
  ``rte_eth_bond_slaves_get``
  will be replaced by:
  ``rte_eth_bond_8023ad_member_info``,
  ``rte_eth_bond_active_members_get``,
  ``rte_eth_bond_member_add``,
  ``rte_eth_bond_member_remove``, and
  ``rte_eth_bond_members_get``.

* cryptodev: The elliptic curve asymmetric private and public keys can be maintained
  per session. These keys are moved from per packet ``rte_crypto_ecdsa_op_param`` and
  ``rte_crypto_sm2_op_param`` to generic EC xform ``rte_crypto_ec_xform``.

* security: Structures ``rte_security_ops`` and ``rte_security_ctx`` were moved to
  internal library headers not visible to application.

* mldev: Updated the structure ``rte_ml_model_info`` to support input and output
  with arbitrary shapes.
  Updated ``rte_ml_op``, ``rte_ml_io_quantize`` and ``rte_ml_io_dequantize``
  to support an array of ``rte_ml_buff_seg``.

* pcapng: The time parameters were removed
  from the functions ``rte_pcapng_copy`` and ``rte_pcapng_write_stats``.


ABI Changes
-----------

* ethdev: Added ``recycle_tx_mbufs_reuse`` and ``recycle_rx_descriptors_refill``
  fields to ``rte_eth_dev`` structure.

* ethdev: Structure ``rte_eth_fp_ops`` was affected to add
  ``recycle_tx_mbufs_reuse`` and ``recycle_rx_descriptors_refill``
  fields, to move ``rxq`` and ``txq`` fields, to change the size of
  ``reserved1`` and ``reserved2`` fields.

* ethdev: Added ``algorithm`` field to ``rte_eth_rss_conf`` structure
  for RSS hash algorithm.

* ethdev: Added ``rss_algo_capa`` field to ``rte_eth_dev_info`` structure
  for reporting RSS hash algorithm capability.

* security: struct ``rte_security_ipsec_sa_options`` was updated
  due to inline out-of-place feature addition.


Tested Platforms
----------------

* Intel\ |reg| platforms with Intel\ |reg| NICs combinations

  * CPU

    * Intel Atom\ |reg| P5342 processor
    * Intel\ |reg| Atom\ |trade| x74xxRE
    * Intel\ |reg| Atom\ |trade| CPU C3758 @ 2.20GHz
    * Intel\ |reg| Xeon\ |reg| CPU D-1553N @ 2.30GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2699 v4 @ 2.20GHz
    * Intel\ |reg| Xeon\ |reg| D-1747NTE CPU @ 2.50GHz
    * Intel\ |reg| Xeon\ |reg| D-2796NT CPU @ 2.00GHz
    * Intel\ |reg| Xeon\ |reg| Gold 6139 CPU @ 2.30GHz
    * Intel\ |reg| Xeon\ |reg| Gold 6140M CPU @ 2.30GHz
    * Intel\ |reg| Xeon\ |reg| Gold 6252N CPU @ 2.30GHz
    * Intel\ |reg| Xeon\ |reg| Gold 6348 CPU @ 2.60GHz
    * Intel\ |reg| Xeon\ |reg| Platinum 8280M CPU @ 2.70GHz
    * Intel\ |reg| Xeon\ |reg| Platinum 8380 CPU @ 2.30GHz
    * Intel\ |reg| Xeon\ |reg| Platinum 8490H
    * GENUINE INTEL\ |reg| XEON\ |reg|

  * OS:

    * CBL Mariner 2.0
    * Fedora 38
    * FreeBSD 13.2
    * OpenAnolis OS 8.8
    * Red Hat Enterprise Linux Server release 8.7
    * Red Hat Enterprise Linux Server release 9.2
    * SUSE Linux Enterprise Server 15 SP5
    * Ubuntu 22.04.3

  * NICs:

    * Intel\ |reg| Ethernet Controller E810-C for SFP (4x25G)

      * Firmware version: 4.40 0x8001c301 1.3492.0
      * Device id (pf/vf): 8086:1593 / 8086:1889
      * Driver version(out-tree): 1.13.1_1_g565e8ce94_dirty (ice)
      * Driver version(in-tree): 5.15.0-82-generic (Ubuntu22.04.3)/ 5.14.0-284.11.1.rt14.296.el9_2.x86_64 (RHEL9.2)/ 5.15.129-rt67 (Ubuntu22.04.3)(ice)
      * OS Default DDP: 1.3.36.0
      * COMMS DDP: 1.3.46.0
      * Wireless Edge DDP: 1.3.14.0

    * Intel\ |reg| Ethernet Controller E810-C for QSFP (2x100G)

      * Firmware version: 4.40 0x8001c2f1 1.3492.0
      * Device id (pf/vf): 8086:1592 / 8086:1889
      * Driver version(out-tree): 1.13.1_1_g565e8ce94_dirty (ice)
      * Driver version(in-tree): 5.15.55.1-1.cm2-5464b22cac7+ (CBL Mariner 2.0) (ice)
      * OS Default DDP: 1.3.36.0
      * COMMS DDP: 1.3.46.0
      * Wireless Edge DDP: 1.3.14.0

    * Intel\ |reg| Ethernet Controller E810-XXV for SFP (2x25G)

      * Firmware version: 4.40 0x8001c2f5 1.3492.0
      * Device id (pf/vf): 8086:159b / 8086:1889
      * Driver version: 1.13.1_1_g565e8ce94_dirty (ice)
      * OS Default DDP: 1.3.36.0
      * COMMS DDP: 1.3.46.0

    * Intel\ |reg| Ethernet Connection E823-C for QSFP

      * Firmware version: 3.33 0x8001b295 1.3443.0
      * Device id (pf/vf): 8086:188b / 8086:1889
      * Driver version: 1.13.1_1_g565e8ce94_dirty (ice)
      * OS Default DDP: 1.3.36.0
      * COMMS DDP: 1.3.46.0
      * Wireless Edge DDP: 1.3.14.0

    * Intel\ |reg| Ethernet Connection E823-L for QSFP

      * Firmware version: 3.33 0x8001b4b0 1.3429.0
      * Device id (pf/vf): 8086:124c / 8086:1889
      * Driver version: 1.13.1_1_g565e8ce94_dirty (ice)
      * OS Default DDP: 1.3.36.0
      * COMMS DDP: 1.3.46.0
      * Wireless Edge DDP: 1.3.14.0

    * Intel\ |reg| Ethernet Connection E822-L for backplane

      * Firmware version: 3.33 0x8001b4b6 1.3429.0
      * Device id (pf/vf): 8086:1897 / 8086:1889
      * Driver version: 1.13.1_1_g565e8ce94_dirty (ice)
      * OS Default DDP: 1.3.36.0
      * COMMS DDP: 1.3.46.0
      * Wireless Edge DDP: 1.3.14.0

    * Intel\ |reg| 82599ES 10 Gigabit Ethernet Controller

      * Firmware version: 0x000161bf
      * Device id (pf/vf): 8086:10fb / 8086:10ed
      * Driver version(out-tree): 5.19.6 (ixgbe)
      * Driver version(in-tree): 5.15.0-82-generic (Ubuntu22.04.3)/ 5.14.0-284.11.1.el9_2.x86_64 (RHEL9.2)(ixgbe)

    * Intel\ |reg| Ethernet Converged Network Adapter X710-DA4 (4x10G)

      * Firmware version: 9.30 0x8000e606 1.3429.0
      * Device id (pf/vf): 8086:1572 / 8086:154c
      * Driver version(out-tree): 2.23.17 (i40e)

    * Intel\ |reg| Corporation Ethernet Connection X722 for 10GbE SFP+ (2x10G)

      * Firmware version: 6.20 0x80003d82 1.3353.0
      * Device id (pf/vf): 8086:37d0 / 8086:37cd
      * Driver version(out-tree): 2.23.17 (i40e)
      * Driver version(in-tree): 5.14.0-284.11.1.el9_2.x86_64 (RHEL9.2)(i40e)

    * Intel\ |reg| Corporation Ethernet Connection X722 for 10GBASE-T

      * Firmware version: 6.20 0x80003d3e 1.2935.0
      * Device id (pf/vf): 8086:37d2 / 8086:37cd
      * Driver version(out-tree): 2.23.17 (i40e)
      * Driver version(in-tree): 5.14.0-284.11.1.el9_2.x86_64 (RHEL9.2) (i40e)

    * Intel\ |reg| Ethernet Converged Network Adapter XXV710-DA2 (2x25G)

      * Firmware version: 9.30 0x8000e5f5 1.3429.0
      * Device id (pf/vf): 8086:158b / 8086:154c
      * Driver version(out-tree): 2.23.17 (i40e)
      * Driver version(in-tree): 5.15.0-82-generic (Ubuntu22.04.3)/5.14.0-284.11.1.el9_2.x86_64 (RHEL9.2)(i40e)

    * Intel\ |reg| Ethernet Converged Network Adapter XL710-QDA2 (2X40G)

      * Firmware version(PF): 9.30 0x8000e5ee 1.3429.0
      * Device id (pf/vf): 8086:1583 / 8086:154c
      * Driver version(out-tree): 2.23.17 (i40e)

    * Intel\ |reg| Ethernet Controller I225-LM

      * Firmware version: 1.3, 0x800000c9
      * Device id (pf): 8086:15f2
      * Driver version(in-tree): 5.15.0-82-generic (Ubuntu22.04.3)(igc)

    * Intel\ |reg| Ethernet Controller I226-LM

      * Firmware version: 2.14, 0x8000028c
      * Device id (pf): 8086:125b
      * Driver version(in-tree): 5.15.0-82-generic (Ubuntu22.04.3)(igc)

    * Intel Corporation I350 Gigabit Network Connection

      * Firmware version: 1.63, 0x80001001
      * Device id (pf/vf): 8086:1521 / 8086:1520
      * Driver version(in-tree): 5.15.0-60-generic (Ubuntu22.04.3)(igb)

* Intel\ |reg| platforms with NVIDIA\ |reg| NICs combinations

  * CPU:

    * Intel\ |reg| Xeon\ |reg| Gold 6154 CPU @ 3.00GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2697A v4 @ 2.60GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2697 v3 @ 2.60GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2680 v2 @ 2.80GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2670 0 @ 2.60GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2650 v4 @ 2.20GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2650 v3 @ 2.30GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2640 @ 2.50GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2650 0 @ 2.00GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2620 v4 @ 2.10GHz

  * OS:

    * Red Hat Enterprise Linux release 9.1 (Plow)
    * Red Hat Enterprise Linux release 8.6 (Ootpa)
    * Red Hat Enterprise Linux release 8.4 (Ootpa)
    * Red Hat Enterprise Linux Server release 7.9 (Maipo)
    * Red Hat Enterprise Linux Server release 7.6 (Maipo)
    * Ubuntu 22.04
    * Ubuntu 20.04
    * SUSE Enterprise Linux 15 SP2

  * OFED:

    * MLNX_OFED 23.07-0.5.1.2 and above

  * upstream kernel:

    * Linux 6.7.0-rc1 and above

  * rdma-core:

    * rdma-core-48.0 and above

  * NICs

    * NVIDIA\ |reg| ConnectX\ |reg|-4 Lx 25G MCX4121A-ACAT (2x25G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1015
      * Firmware version: 14.32.1010 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-4 Lx 50G MCX4131A-GCAT (1x50G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1015
      * Firmware version: 14.32.1010 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-5 100G MCX516A-CCAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.35.2000 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-5 100G MCX516A-CCAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.38.1900 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-5 100G MCX556A-ECAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.38.1900 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-5 100G MCX556A-EDAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.38.1900 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-5 Ex EN 100G MCX516A-CDAT (2x100G)

      * Host interface: PCI Express 4.0 x16
      * Device ID: 15b3:1019
      * Firmware version: 16.38.1900 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-6 Dx EN 100G MCX623106AN-CDAT (2x100G)

      * Host interface: PCI Express 4.0 x16
      * Device ID: 15b3:101d
      * Firmware version: 22.38.1900 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-6 Lx EN 25G MCX631102AN-ADAT (2x25G)

      * Host interface: PCI Express 4.0 x8
      * Device ID: 15b3:101f
      * Firmware version: 26.38.1900 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-7 200G CX713106AE-HEA_QP1_Ax (2x200G)

      * Host interface: PCI Express 5.0 x16
      * Device ID: 15b3:1021
      * Firmware version: 28.38.1900 and above

* NVIDIA\ |reg| BlueField\ |reg| SmartNIC

  * NVIDIA\ |reg| BlueField\ |reg|-2 SmartNIC MT41686 - MBF2H332A-AEEOT_A1 (2x25G)

    * Host interface: PCI Express 3.0 x16
    * Device ID: 15b3:a2d6
    * Firmware version: 24.38.1002 and above

  * NVIDIA\ |reg| BlueField\ |reg|-3 P-Series DPU MT41692 - 900-9D3B6-00CV-AAB (2x200G)

    * Host interface: PCI Express 5.0 x16
    * Device ID: 15b3:a2dc
    * Firmware version: 32.38.1002 and above

  * Embedded software:

    * Ubuntu 22.04
    * MLNX_OFED 23.07-0.5.0.0 and above
    * DOCA_2.2.0_BSP_4.2.0_Ubuntu_22.04-2.23-07
    * DPDK application running on ARM cores

* IBM Power 9 platforms with NVIDIA\ |reg| NICs combinations

  * CPU:

    * POWER9 2.2 (pvr 004e 1202)

  * OS:

    * Ubuntu 20.04

  * NICs:

    * NVIDIA\ |reg| ConnectX\ |reg|-6 Dx 100G MCX623106AN-CDAT (2x100G)

      * Host interface: PCI Express 4.0 x16
      * Device ID: 15b3:101d
      * Firmware version: 22.38.1900 and above

    * NVIDIA\ |reg| ConnectX\ |reg|-7 200G CX713106AE-HEA_QP1_Ax (2x200G)

      * Host interface: PCI Express 5.0 x16
      * Device ID: 15b3:1021
      * Firmware version: 28.38.1900 and above

  * OFED:

    * MLNX_OFED 23.07-0.5.1.2

23.11.1 Release Notes
---------------------


23.11.1 Fixes
~~~~~~~~~~~~~

* 23.11.1-rc1
* app/crypto-perf: add missing op resubmission
* app/crypto-perf: fix copy segment size
* app/crypto-perf: fix data comparison
* app/crypto-perf: fix encrypt operation verification
* app/crypto-perf: fix next segment mbuf
* app/crypto-perf: fix out-of-place mbuf size
* app/crypto-perf: verify strdup return
* app/dma-perf: verify strdup return
* app/dumpcap: verify strdup return
* app/graph: fix build reason
* app/pdump: verify strdup return
* app/testpmd: fix --stats-period option check
* app/testpmd: fix GRO packets flush on timeout
* app/testpmd: fix async flow create failure handling
* app/testpmd: fix async indirect action list creation
* app/testpmd: fix auto-completion for indirect action list
* app/testpmd: fix burst option parsing
* app/testpmd: fix crash in multi-process forwarding
* app/testpmd: fix error message for invalid option
* app/testpmd: fix flow modify tag typo
* app/testpmd: hide --bitrate-stats in help if disabled
* app/testpmd: return if no packets in GRO heavy weight mode
* app/testpmd: verify strdup return
* build: fix linker warnings about undefined symbols
* build: fix reasons conflict
* build: link static libs with whole-archive in subproject
* build: pass cflags in subproject
* buildtools/cmdline: fix IP address initializer
* buildtools/cmdline: fix generated code for IP addresses
* bus/dpaa: verify strdup return
* bus/fslmc: verify strdup return
* bus/vdev: fix devargs in secondary process
* bus/vdev: verify strdup return
* ci: update versions of actions in GHA
* common/cnxk: fix RSS RETA configuration
* common/cnxk: fix Tx MTU configuration
* common/cnxk: fix VLAN check for inner header
* common/cnxk: fix inline device pointer check
* common/cnxk: fix link config for SDP
* common/cnxk: fix mbox region copy
* common/cnxk: fix mbox struct attributes
* common/cnxk: fix memory leak in CPT init
* common/cnxk: fix possible out-of-bounds access
* common/cnxk: remove CN9K inline IPsec FP opcodes
* common/cnxk: remove dead code
* common/mlx5: fix calloc parameters
* common/mlx5: fix duplicate read of general capabilities
* common/mlx5: fix query sample info capability
* common/qat: fix legacy flag
* common/sfc_efx/base: use C11 static assert
* config: fix CPU instruction set for cross-build
* crypto/cnxk: fix CN9K ECDH public key verification
* crypto/qat: fix crash with CCM null AAD pointer
* cryptodev: remove unused extern variable
* dma/dpaa2: fix logtype register
* dma/idxd: verify strdup return
* dmadev: fix calloc parameters
* doc: add --latencystats option in testpmd guide
* doc: add link speeds configuration in features table
* doc: add traffic manager in features table
* doc: fix aging poll frequency option in cnxk guide
* doc: fix commands in eventdev test tool guide
* doc: fix configuration in baseband 5GNR driver guide
* doc: fix default IP fragments maximum in programmer guide
* doc: fix typo in packet framework guide
* doc: fix typo in profiling guide
* doc: fix typos in cryptodev overview
* doc: remove cmdline polling mode deprecation notice
* doc: update link to Windows DevX in mlx5 guide
* drivers/net: fix buffer overflow for packet types list
* dts: fix smoke tests driver regex
* dts: strip whitespaces from stdout and stderr
* eal/x86: add AMD vendor check for TSC calibration
* eal: verify strdup return
* ethdev: fix NVGRE encap flow action description
* event/cnxk: fix dequeue timeout configuration
* event/cnxk: verify strdup return
* event/dlb2: remove superfluous memcpy
* eventdev/crypto: fix enqueueing
* eventdev: fix Doxygen processing of vector struct
* eventdev: fix calloc parameters
* eventdev: improve Doxygen comments on configure struct
* examples/ipsec-secgw: fix Rx queue ID in Rx callback
* examples/ipsec-secgw: fix cryptodev to SA mapping
* examples/ipsec-secgw: fix typo in error message
* examples/ipsec-secgw: fix width of variables
* examples/l3fwd: fix Rx over not ready port
* examples/l3fwd: fix Rx queue configuration
* examples/packet_ordering: fix Rx with reorder mode disabled
* examples/qos_sched: fix memory leak in args parsing
* examples/vhost: verify strdup return
* gro: fix reordering of packets
* hash: remove some dead code
* kernel/freebsd: fix module build on FreeBSD 14
* lib: add newline in logs
* lib: remove redundant newline from logs
* lib: use dedicated logtypes and macros
* ml/cnxk: fix xstats calculation
* net/af_xdp: fix leak on XSK configuration failure
* net/af_xdp: fix memzone leak on config failure
* net/bnx2x: fix calloc parameters
* net/bnx2x: fix warnings about memcpy lengths
* net/bnxt: fix 50G and 100G forced speed
* net/bnxt: fix array overflow
* net/bnxt: fix backward firmware compatibility
* net/bnxt: fix deadlock in ULP timer callback
* net/bnxt: fix null pointer dereference
* net/bnxt: fix number of Tx queues being created
* net/bnxt: fix speed change from 200G to 25G on Thor
* net/bnxt: modify locking for representor Tx
* net/bonding: fix flow count query
* net/cnxk: add cookies check for multi-segment offload
* net/cnxk: fix MTU limit
* net/cnxk: fix Rx packet format check condition
* net/cnxk: fix aged flow query
* net/cnxk: fix buffer size configuration
* net/cnxk: fix flow RSS configuration
* net/cnxk: fix indirect mbuf handling in Tx
* net/cnxk: fix mbuf fields in multi-segment Tx
* net/cnxk: improve Tx performance for SW mbuf free
* net/ena/base: fix metrics excessive memory consumption
* net/ena/base: limit exponential backoff
* net/ena/base: restructure interrupt handling
* net/ena: fix fast mbuf free
* net/ena: fix mbuf double free in fast free mode
* net/failsafe: fix memory leak in args parsing
* net/gve: fix DQO for chained descriptors
* net/hns3: enable PFC for all user priorities
* net/hns3: fix VF multiple count on one reset
* net/hns3: fix disable command with firmware
* net/hns3: fix reset level comparison
* net/hns3: refactor PF mailbox message struct
* net/hns3: refactor VF mailbox message struct
* net/hns3: refactor handle mailbox function
* net/hns3: refactor send mailbox function
* net/hns3: remove QinQ insert support for VF
* net/hns3: support new device
* net/i40e: remove incorrect 16B descriptor read block
* net/i40e: remove redundant judgment in flow parsing
* net/iavf: fix crash on VF start
* net/iavf: fix memory leak on security context error
* net/iavf: fix no polling mode switching
* net/iavf: remove error logs for VLAN offloading
* net/iavf: remove incorrect 16B descriptor read block
* net/ice: fix link update
* net/ice: fix memory leaks
* net/ice: fix tunnel TSO capabilities
* net/ice: remove incorrect 16B descriptor read block
* net/igc: fix timesync disable
* net/ionic: fix RSS query
* net/ionic: fix device close
* net/ionic: fix missing volatile type for cqe pointers
* net/ixgbe: fix memoy leak after device init failure
* net/ixgbe: increase VF reset timeout
* net/ixgbevf: fix RSS init for x550 NICs
* net/mana: fix memory leak on MR allocation
* net/mana: handle MR cache expansion failure
* net/mana: prevent values overflow returned from RDMA layer
* net/memif: fix crash with Tx burst larger than 255
* net/memif: fix extra mbuf refcnt update in zero copy Tx
* net/mlx5/hws: check not supported fields in VXLAN
* net/mlx5/hws: enable multiple integrity items
* net/mlx5/hws: fix ESP flow matching validation
* net/mlx5/hws: fix VLAN inner type
* net/mlx5/hws: fix VLAN item in non-relaxed mode
* net/mlx5/hws: fix direct index insert on depend WQE
* net/mlx5/hws: fix memory access in L3 decapsulation
* net/mlx5/hws: fix port ID for root table
* net/mlx5/hws: fix tunnel protocol checks
* net/mlx5/hws: skip item when inserting rules by index
* net/mlx5: fix DR context release ordering
* net/mlx5: fix GENEVE TLV option management
* net/mlx5: fix GENEVE option item translation
* net/mlx5: fix HWS meter actions availability
* net/mlx5: fix HWS registers initialization
* net/mlx5: fix IP-in-IP tunnels recognition
* net/mlx5: fix VLAN ID in flow modify
* net/mlx5: fix VLAN handling in meter split
* net/mlx5: fix age position in hairpin split
* net/mlx5: fix async flow create error handling
* net/mlx5: fix condition of LACP miss flow
* net/mlx5: fix connection tracking action validation
* net/mlx5: fix conntrack action handle representation
* net/mlx5: fix counters map in bonding mode
* net/mlx5: fix drop action release timing
* net/mlx5: fix error packets drop in regular Rx
* net/mlx5: fix flow action template expansion
* net/mlx5: fix flow configure validation
* net/mlx5: fix flow counter cache starvation
* net/mlx5: fix flow tag modification
* net/mlx5: fix indirect action async job initialization
* net/mlx5: fix jump action validation
* net/mlx5: fix meter policy priority
* net/mlx5: fix modify flex item
* net/mlx5: fix non-masked indirect list meter translation
* net/mlx5: fix parameters verification in HWS table create
* net/mlx5: fix rollback on failed flow configure
* net/mlx5: fix stats query crash in secondary process
* net/mlx5: fix sync flow meter action
* net/mlx5: fix sync meter processing in HWS
* net/mlx5: fix template clean up of FDB control flow rule
* net/mlx5: fix use after free when releasing Tx queues
* net/mlx5: fix warning about copy length
* net/mlx5: prevent ioctl failure log flooding
* net/mlx5: prevent querying aged flows on uninit port
* net/mlx5: remove GENEVE options length limitation
* net/mlx5: remove device status check in flow creation
* net/mlx5: remove duplication of L3 flow item validation
* net/netvsc: fix VLAN metadata parsing
* net/nfp: fix IPsec data endianness
* net/nfp: fix NFD3 metadata process
* net/nfp: fix NFDk metadata process
* net/nfp: fix Rx descriptor
* net/nfp: fix Rx memory leak
* net/nfp: fix calloc parameters
* net/nfp: fix device close
* net/nfp: fix device resource freeing
* net/nfp: fix getting firmware VNIC version
* net/nfp: fix initialization failure flow
* net/nfp: fix resource leak for CoreNIC firmware
* net/nfp: fix resource leak for PF initialization
* net/nfp: fix resource leak for VF
* net/nfp: fix resource leak for device initialization
* net/nfp: fix resource leak for exit of CoreNIC firmware
* net/nfp: fix resource leak for exit of flower firmware
* net/nfp: fix resource leak for flower firmware
* net/nfp: fix switch domain free check
* net/nfp: fix uninitialized variable
* net/nfp: free switch domain ID on close
* net/nfp: verify strdup return
* net/sfc: fix calloc parameters
* net/softnic: fix include of log library
* net/tap: do not overwrite flow API errors
* net/tap: fix traffic control handle calculation
* net/thunderx: fix DMAC control register update
* net/virtio: fix vDPA device init advertising control queue
* net/virtio: remove duplicate queue xstats
* net/vmxnet3: fix initialization on FreeBSD
* net/vmxnet3: ignore Rx queue interrupt setup on FreeBSD
* net: add macros for VLAN metadata parsing
* net: fix TCP/UDP checksum with padding data
* pipeline: fix calloc parameters
* rawdev: fix calloc parameters
* rcu: fix acked token in debug log
* rcu: use atomic operation on acked token
* regexdev: fix logtype register
* telemetry: fix connected clients count
* telemetry: fix empty JSON dictionaries
* test/cfgfile: fix typo in error messages
* test/event: fix crash in Tx adapter freeing
* test/event: skip test if no driver is present
* test/mbuf: fix external mbuf case with assert enabled
* test/power: fix typo in error message
* test: assume C source files are UTF-8 encoded
* test: do not count skipped tests as executed
* test: fix probing in secondary process
* test: verify strdup return
* vdpa/mlx5: fix queue enable drain CQ
* version: 23.11.1-rc2
* vhost: fix VDUSE device destruction failure
* vhost: fix deadlock during vDPA SW live migration
* vhost: fix memory leak in Virtio Tx split path
* vhost: fix virtqueue access check in VDUSE setup
* vhost: fix virtqueue access check in datapath
* vhost: fix virtqueue access check in vhost-user setup

23.11.1 Validation
~~~~~~~~~~~~~~~~~~

* RedHat Testing:

    * Test scenarios:

        * VM with device assignment(PF) throughput testing(1G hugepage size)
        * VM with device assignment(PF) throughput testing(2M hugepage size)
        * VM with device assignment(VF) throughput testing
        * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing
        * PVP vhost-user 2Q throughput testing
        * PVP vhost-user 1Q - cross numa node throughput testing
        * VM with vhost-user 2 queues throughput testing
        * vhost-user reconnect with dpdk-client, qemu-server qemu reconnect
        * vhost-user reconnect with dpdk-client, qemu-server ovs reconnect
        * PVP  reconnect with dpdk-client, qemu-server
        * PVP 1Q live migration testing
        * PVP 1Q cross numa node live migration testing
        * VM with ovs+dpdk+vhost-user 1Q live migration testing
        * VM with ovs+dpdk+vhost-user 1Q live migration testing (2M)
        * VM with ovs+dpdk+vhost-user 2Q live migration testing
        * VM with ovs+dpdk+vhost-user 4Q live migration testing
        * Host PF + DPDK testing
        * Host VF + DPDK testing

    * Test Versions and device:

        * RHEL 9.4
        * qemu-kvm-8.2.0
        * kernel 5.14
        * libvirt 10.0
        * X540-AT2 NIC(ixgbe, 10G)

* Nvidia(R) Testing:

    * Test scenarios:

        * Send and receive multiple types of traffic.
        * testpmd xstats counter test.
        * testpmd timestamp test.
        * Changing/checking link status through testpmd.
        * rte_flow tests (https://doc.dpdk.org/guides/nics/mlx5.html#supported-hardware-offloads)
        * RSS tests.
        * VLAN filtering, stripping, and insertion tests.
        * Checksum and TSO tests.
        * ptype tests.
        * link_status_interrupt example application tests.
        * l3fwd-power example application tests.
        * Multi-process example applications tests.
        * Hardware LRO tests.
        * Buffer Split tests.
        * Tx scheduling tests.

    * Test platform:

        * NIC: ConnectX-6 Dx / OS: Ubuntu 20.04 / Driver: MLNX_OFED_LINUX-24.04-0.6.6.0 / Firmware: 22.41.1000
        * NIC: ConnectX-7 / OS: Ubuntu 20.04 / Driver: MLNX_OFED_LINUX-24.04-0.6.6.0 / Firmware: 28.41.1000
        * DPU: BlueField-2 / DOCA SW version: 2.7.0 / Firmware: 24.41.1000

    * OS/driver combinations:

        * Debian 12 with MLNX_OFED_LINUX-24.01-0.3.3.1.
        * Ubuntu 20.04.6 with MLNX_OFED_LINUX-24.01-0.3.3.1.
        * Ubuntu 22.04.4 with MLNX_OFED_LINUX-24.04-0.6.6.0.
        * Ubuntu 20.04.6 with rdma-core master (311c591).
        * Ubuntu 20.04.6 with rdma-core v28.0.
        * Fedora 40 with rdma-core v48.0.
        * Fedora 41 (Rawhide) with rdma-core v51.0.
        * OpenSUSE Leap 15.5 with rdma-core v42.0.
        * Windows Server 2019 with Clang 16.0.6.

* Intel(R) Testing:

    * Basic NIC testing

        * Build & CFLAG compile: cover the build test combination with latest GCC/Clang version and the popular OS revision such as Ubuntu23.10, Ubuntu22.04, Fedora39, RHEL8.9, RHEL9.2, FreeBSD14.0, SUSE15, CentOS7.9, openEuler22.03-SP2，OpenAnolis8.8 etc.
        * PF(i40e, ixgbe): test scenarios including RTE_FLOW/TSO/Jumboframe/checksum offload/VLAN/VXLAN, etc.
        * VF(i40e, ixgbe): test scenarios including VF-RTE_FLOW/TSO/Jumboframe/checksum offload/VLAN/VXLAN, etc.
        * PF/VF(ice): test scenarios including Switch features/Package Management/Flow Director/Advanced Tx/Advanced RSS/ACL/DCF/Flexible Descriptor, etc.
        * Intel NIC single core/NIC performance: test scenarios including PF/VF single core performance test, etc.
        * IPsec: test scenarios including ipsec/ipsec-gw/ipsec library basic test - QAT&SW/FIB library, etc.

    * Basic cryptodev and virtio testing

        * Virtio: both function and performance test are covered. Such as PVP/Virtio_loopback/virtio-user loopback/virtio-net VM2VM perf testing/VMAWARE ESXI 8.0, etc.
        * Cryptodev Function test: Cryptodev API testing/CompressDev ISA-L/QAT/ZLIB PMD Testing/FIPS, etc.
        * Cryptodev Performance test: test scenarios including Thoughput Performance/Cryptodev Latency, etc.

23.11.1 Known Issues
~~~~~~~~~~~~~~~~~~~~

* Start dpdk-pdump in VM with virtio-0.95 protocol failed

    Fix available in upstream.
