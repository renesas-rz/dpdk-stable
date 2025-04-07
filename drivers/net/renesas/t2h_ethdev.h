/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Renesas Electronics Corporation
 */
#ifndef __T2H_ETHDEV_H__
#define __T2H_ETHDEV_H__

#include <rte_ethdev.h>
#include <rte_io.h>

#include "t2h_regs.h"
#include "t2h_util.h"

#define T2H_EQOS_MAX_TX_BD_RING_SIZE            (512)

#define T2H_EQOS_CHAN0                          0
#define T2H_EQOS_MAC_HI_DCS_SHIFT               16

#define BITS_PER_LONG                           (__SIZEOF_LONG__ * 8)
#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

/* Multiple RX Buffer size */
#define T2H_EQOS_DEF_BUF_SIZE                   1536
#define T2H_EQOS_BUF_SIZE_2KB                   2048
#define T2H_EQOS_BUF_SIZE_4KB                   4096
#define T2H_EQOS_BUF_SIZE_8KB                   8188
#define T2H_EQOS_BUF_SIZE_16KB                  16368

/* DMA Default SIZE */
#define T2H_EQOS_DMA_DEF_RX_SIZE                512
#define T2H_EQOS_DMA_DEF_TX_SIZE                512

/* Default Watchdog Timer value */
#define T2H_EQOS_DEF_DMA_RWT                    0xa0

/* Default MAC Operating Mode */
#define T2H_EQOS_MAC_CORE_INIT                                                       \
	(T2H_EQOS_MAC_CONFIG_JD | T2H_EQOS_MAC_CONFIG_BE | T2H_EQOS_MAC_CONFIG_DCRS | \
	 T2H_EQOS_MAC_CONFIG_JE)
#define T2H_EQOS_MAC_INT_DEF_ENABLE             (0)

#define __iomem
#if defined(RTE_ARCH_ARM)
#if defined(RTE_ARCH_64)
#define dcbf(p)                                                    \
	{                                                          \
		asm volatile("dc cvac, %0" : : "r"(p) : "memory"); \
	}
#define dcbf_64(p)                              dcbf(p)

#else /* RTE_ARCH_32 */
#define dcbf(p)                                 RTE_SET_USED(p)
#define dcbf_64(p)                              dcbf(p)
#endif

#else
#define dcbf(p)                                 RTE_SET_USED(p)
#define dcbf_64(p)                              dcbf(p)
#endif

#define T2H_EQOS_MAX_RX_PKT_LEN                 3000
#define T2H_EQOS_MAX_Q                          4
#define T2H_EQOS_MAX_MAC_ADDR                   32

#define T2H_EQOS_VLAN_N_VID                     4096

#define T2H_EQOS_QUEUE_NUM_TWO                  2
#define T2H_EQOS_QUEUE_NUM_THREE                3
#define T2H_EQOS_QUEUE_NUM_FOUR                 4
#define T2H_EQOS_QUEUE_NUM_FIVE                 5
#define T2H_EQOS_QUEUE_NUM_SIX                  6
#define T2H_EQOS_QUEUE_NUM_SEVEN                7
#define T2H_EQOS_QUEUE_NUM_EIGHT                8

#define T2H_EQOS_TWO_QUEUE_Q_0                  0xC3
#define T2H_EQOS_TWO_QUEUE_Q_1                  0x3C
#define T2H_EQOS_THREE_QUEUE_Q_0                0x81
#define T2H_EQOS_THREE_QUEUE_Q_1                0x46
#define T2H_EQOS_THREE_QUEUE_Q_2                0x38
#define T2H_EQOS_FOUR_QUEUE_Q_0                 0x81
#define T2H_EQOS_FOUR_QUEUE_Q_0                 0x81
#define T2H_EQOS_FOUR_QUEUE_Q_1                 0x42
#define T2H_EQOS_FOUR_QUEUE_Q_2                 0x24
#define T2H_EQOS_FOUR_QUEUE_Q_3                 0x18
#define T2H_EQOS_FIVE_QUEUE_Q_0                 0x21
#define T2H_EQOS_FIVE_QUEUE_Q_1                 0x12
#define T2H_EQOS_FIVE_QUEUE_Q_2                 0xC
#define T2H_EQOS_SIX_QUEUE_Q_0                  0x9
#define T2H_EQOS_SIX_QUEUE_Q_1                  0x6
#define T2H_EQOS_SEVEN_QUEUE_Q_1                0x6
#define T2H_EQOS_QUEUE_MAP_0                    0x1
#define T2H_EQOS_QUEUE_MAP_1                    0x2
#define T2H_EQOS_QUEUE_MAP_2                    0x4
#define T2H_EQOS_QUEUE_MAP_3                    0x8
#define T2H_EQOS_QUEUE_MAP_4                    0x10
#define T2H_EQOS_QUEUE_MAP_5                    0x20
#define T2H_EQOS_QUEUE_MAP_6                    0x40
#define T2H_EQOS_QUEUE_MAP_7                    0x80

#define max(a, b)                               RTE_MAX(a, b)

#define T2H_EQOS_RX_QUEUE_CLEAR(queue)          ~(GENMASK(1, 0) << ((queue)*2))
#define T2H_EQOS_RX_DCB_QUEUE_ENABLE(queue)     BIT(((queue)*2) + 1)

#define T2H_EQOS_UDELAY(x)                      rte_delay_us(x)
#define T2H_EQOS_VLAN_TABLE_BIT(vlan_id)        (1UL << ((vlan_id)&0x3F))
#define T2H_EQOS_VLAN_TABLE_IDX(vlan_id)        ((vlan_id) >> 6)

#define T2H_EQOS_UPPER_32_BITS(n)               ((uint32_t)(((n) >> 16) >> 16))
#define T2H_EQOS_LOWER_32_BITS(n)               ((uint32_t)(n))

/* To dump the MAC regs */
#define T2H_EQOS_MAC_REG_NUM                    1000

/* To dump the MAC regs */
#define T2H_EQOS_DMA_REG_NUM                    24

/* To dump the DMA regs */
#define T2H_EQOS_DMA_CH_NB_MAX                  8

/* Total octets in header. */
#define T2H_EQOS_HLEN                           14

/* Min. octets in frame sans FCS */
#define T2H_EQOS_ZLEN                           60

/* Min. octets in frame sans FCS */
#define T2H_EQOS_JUMBO_LEN                      9000

/* To dump the regs */
#define T2H_EQOS_REG_NUM (T2H_EQOS_MAC_REG_NUM + T2H_EQOS_DMA_REG_NUM + T2H_EQOS_DMA_CH_NB_MAX * 18)

#define T2H_EQOS_TIC_COUNTER                    399

#define T2H_EQOS_RXQ_DEF_WEGT                   1
#define T2H_EQOS_TXQ_DEF_WEGT                   50

#define T2H_EQOS_MAC_HIGH_EIGHT                 8
#define T2H_EQOS_MAC_LOW_EIGHT                  8
#define T2H_EQOS_MAC_LOW_SIXTEEN                16
#define T2H_EQOS_MAC_LOW_TWENTY_FOUR            24

#define T2H_EQOS_FULL_MASK                      0xff
#define T2H_EQOS_EMPTY_MASK                     0

#define T2H_EQOS_DMA_RESET_TRY_COUNT            100
#define T2H_EQOS_DMA_RESET_DELAY_TIME           10000

#define T2H_EQOS_SPEED_100                      100
#define T2H_EQOS_SPEED_10                       10

#define T2H_EQOS_DEF_PRIOPRITY                  1
#define T2H_EQOS_QUEUE_REG_OTH                  4

#define T2H_EQOS_DEF_QUEUE_NUM                  1
#define T2H_EQOS_DEF_QUEUE_SUB                  1
#define T2H_EQOS_DEF_QUEUE_BYTE                 256
#define T2H_EQOS_QUEUE_SIZE_4K                  4096
#define T2H_EQOS_RFD_3                          0x3
#define T2H_EQOS_RFD_7                          0x7
#define T2H_EQOS_RFA_1                          0x1
#define T2H_EQOS_RFA_4                          0x4

#define T2H_EQOS_MMC_DEF_CTL                    0x3f

#define T2H_EQOS_VLAN_TIMEOUT_CNT               10
#define T2H_EQOS_VLAN_DELAY_TIME                1

#define T2H_EQOS_MULTICAST_ON                   1
#define T2H_EQOS_MULTICAST_OFF                  0

#define T2H_EQOS_PROMISC_ON                     1
#define T2H_EQOS_PROMISC_OFF                    0

#define T2H_EQOS_VLAN_DEF_NUM                   1
#define T2H_EQOS_VLAN_DEF_NUM_4                 4
#define T2H_EQOS_VLAN_DEF_NUM_8                 8
#define T2H_EQOS_VLAN_DEF_NUM_16                16
#define T2H_EQOS_VLAN_DEF_NUM_24                24
#define T2H_EQOS_VLAN_DEF_NUM_32                32
#define T2H_EQOS_VLANID_HASHTAV_MAX             64
#define T2H_EQOS_VLANID_VALID                   1
#define T2H_EQOS_VLANID_MASK                    1
#define T2H_EQOS_VLANID_CRC_MASK                28
#define T2H_EQOS_VLANID_DIS_COUNT               2
#define T2H_EQOS_VLANID_MAX                     4095
#define T2H_EQOS_VLANID_ZERO                    0

#define T2H_EQOS_HW_FEAT0_VLHASH_SHIFT          4
#define T2H_EQOS_HW_FEAT1_TXFIFOSIZE_SHIFT      6
#define T2H_EQOS_HW_FEAT1_RXFIFOSIZE_SHIFT      0
#define T2H_EQOS_HW_FEAT1_HASH_TB_SZ_SHIFT      24
#define T2H_EQOS_HW_FEAT1_FIFOSIZE_MASK         128

#define T2H_EQOS_REG_WIDTH                      4

struct t2h_eqos_mmc_stats {

	uint64_t txoctetcount_gb;
	uint64_t txpacketscount_gb;
	uint64_t txbroadcastpackets_g;
	uint64_t txmulticastpackets_g;
	uint64_t tx64octets_gb;
	uint64_t tx65to127octets_gb;
	uint64_t tx128to255octets_gb;
	uint64_t tx256to511octets_gb;
	uint64_t tx512to1023octets_gb;
	uint64_t tx1024tomaxoctets_gb;
	uint64_t txunicastpackets_gb;
	uint64_t txmulticastpackets_gb;
	uint64_t txbroadcastpackets_gb;
	uint64_t txunderflowerror;
	uint64_t txsinglecollision_g;
	uint64_t txmultiplecollision_g;
	uint64_t txdeferred;
	uint64_t txlatecollision;
	uint64_t txexcessivecollision;
	uint64_t txcarriererror;
	uint64_t txoctetcount_g;
	uint64_t txpacketcount_g;
	uint64_t txexcessivedeferral;
	uint64_t txpausepackets;
	uint64_t txvlanpackets_g;

	uint64_t rxpacketcount_gb;
	uint64_t rxoctetcount_gb;
	uint64_t rxoctetcount_g;
	uint64_t rxbroadcastpackets_g;
	uint64_t rxmulticastpackets_g;
	uint64_t rxcrcerror;
	uint64_t rxalignmenterror;
	uint64_t rxrunterror;
	uint64_t rxjabbererror;
	uint64_t rxundersize_g;
	uint64_t rxoversize_g;
	uint64_t rx64octets_gb;
	uint64_t rx65to127octets_gb;
	uint64_t rx128to255octets_gb;
	uint64_t rx256to511octets_gb;
	uint64_t rx512to1023octets_gb;
	uint64_t rx1024tomaxoctets_gb;
	uint64_t rxunicastpackets_g;
	uint64_t rxlengtherror;
	uint64_t rxoutofrangetype;
	uint64_t rxpausepackets;
	uint64_t rxfifooverflow;
	uint64_t rxvlanpackets_gb;
	uint64_t rxwatchdogerror;

	uint64_t rxipcintr;

	uint64_t rxipv4_gb;
	uint64_t rxipv4_hderr;
	uint64_t rxipv4_nopay;
	uint64_t rxipv4_frag;
	uint64_t rxipv4_udsbl;
	uint64_t rxipv4_gb_octets;
	uint64_t rxipv4_hderr_octets;
	uint64_t rxipv4_nopay_octets;
	uint64_t rxipv4_frag_octets;
	uint64_t rxipv4_udsbl_octets;

	uint64_t rxipv6_gb_octets;
	uint64_t rxipv6_hderr_octets;
	uint64_t rxipv6_nopay_octets;
	uint64_t rxipv6_gb;
	uint64_t rxipv6_hderr;
	uint64_t rxipv6_nopay;

	uint64_t rxudp_gb;
	uint64_t rxudp_err;
	uint64_t rxtcp_gb;
	uint64_t rxtcp_err;
	uint64_t rxicmp_gb;
	uint64_t rxicmp_err;
	uint64_t rxudp_gb_octets;
	uint64_t rxudp_err_octets;
	uint64_t rxtcp_gb_octets;
	uint64_t rxtcp_err_octets;
	uint64_t rxicmp_gb_octets;
	uint64_t rxicmp_err_octets;
	uint64_t txfpefragmentcntr;
	uint64_t txholdreqcntr;
	uint64_t rxpacketassemblyerrcntr;
	uint64_t rxpacketsmderrcntr;
	uint64_t rxpacketassemblyokcntr;
	uint64_t rxfpefragmentcntr;
};

struct renesas_t2h_private {
	struct rte_eth_dev *dev;
	struct rte_eth_stats stats;
	uint16_t max_rx_queues;
	uint16_t max_tx_queues;
	uint32_t reg_size;
	uint32_t bd_size;
	int uio_fd;
	void *hw_baseaddr_v;
	void *bd_addr_v;
	uint32_t bd_addr_p;
	uint32_t bd_addr_p_r[T2H_EQOS_MAX_Q];
	uint32_t bd_addr_p_t[T2H_EQOS_MAX_Q];
	void *dma_baseaddr_r[T2H_EQOS_MAX_Q];
	void *dma_baseaddr_t[T2H_EQOS_MAX_Q];
	uint32_t dma_rx_size;
	uint32_t dma_tx_size;
	struct t2h_eqos_mmc_stats mmc_stats;
	uint32_t vlan_num;
	uint32_t vlhash;
	unsigned long config_vlans[BITS_TO_LONGS(T2H_EQOS_VLAN_N_VID)];
	uint32_t filter_set[32];
	uint32_t tx_fifo_size;
	uint32_t rx_fifo_size;
	uint32_t rx_queues_to_use;
	uint32_t tx_queues_to_use;
	uint32_t buf_size;
	uint8_t d_size;
	uint8_t d_size_log2;
	uint32_t hash_tb_sz;
	uint32_t promisc;
	uint32_t flag_csum;
	uint32_t version_id;
	uint32_t phy_reg;
};

struct t2h_eqos_xstats {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	int offset;
};

#define T2H_EQOS_MMC_STAT(_string, _var)                            \
	{                                                           \
		_string, offsetof(struct t2h_eqos_mmc_stats, _var), \
	}

static const struct t2h_eqos_xstats t2h_eqos_xstats_strings[] = {

	T2H_EQOS_MMC_STAT("tx_bytes", txoctetcount_gb),
	T2H_EQOS_MMC_STAT("tx_packets", txpacketscount_gb),
	T2H_EQOS_MMC_STAT("tx_broadcast_good", txbroadcastpackets_g),
	T2H_EQOS_MMC_STAT("tx_multicast_good", txmulticastpackets_g),
	T2H_EQOS_MMC_STAT("tx_64_byte_packets", tx64octets_gb),
	T2H_EQOS_MMC_STAT("tx_65_to_127_byte_packets", tx65to127octets_gb),
	T2H_EQOS_MMC_STAT("tx_128_to_255_byte_packets", tx128to255octets_gb),
	T2H_EQOS_MMC_STAT("tx_256_to_511_byte_packets", tx256to511octets_gb),
	T2H_EQOS_MMC_STAT("tx_512_to_1023_byte_packets", tx512to1023octets_gb),
	T2H_EQOS_MMC_STAT("tx_1024_to_max_byte_packets", tx1024tomaxoctets_gb),
	T2H_EQOS_MMC_STAT("tx_unicast_packets", txunicastpackets_gb),
	T2H_EQOS_MMC_STAT("tx_multicast_packets", txmulticastpackets_gb),
	T2H_EQOS_MMC_STAT("tx_broadcast_packets", txbroadcastpackets_gb),
	T2H_EQOS_MMC_STAT("tx_underflow_errors", txunderflowerror),
	T2H_EQOS_MMC_STAT("tx_single_collision", txsinglecollision_g),
	T2H_EQOS_MMC_STAT("tx_multiple_collision", txmultiplecollision_g),
	T2H_EQOS_MMC_STAT("tx_deferred", txdeferred),
	T2H_EQOS_MMC_STAT("tx_late_collision", txlatecollision),
	T2H_EQOS_MMC_STAT("tx_excessive_collision", txexcessivecollision),
	T2H_EQOS_MMC_STAT("tx_carrier_error", txcarriererror),
	T2H_EQOS_MMC_STAT("tx_octet_good", txoctetcount_g),
	T2H_EQOS_MMC_STAT("tx_packet_good", txpacketcount_g),
	T2H_EQOS_MMC_STAT("tx_excessive_deferral", txexcessivedeferral),
	T2H_EQOS_MMC_STAT("tx_pause_frames", txpausepackets),
	T2H_EQOS_MMC_STAT("tx_vlan_packets", txvlanpackets_g),

	T2H_EQOS_MMC_STAT("rx_packets", rxpacketcount_gb),
	T2H_EQOS_MMC_STAT("rx_bytes", rxoctetcount_gb),
	T2H_EQOS_MMC_STAT("rx_bytes_good", rxoctetcount_g),
	T2H_EQOS_MMC_STAT("rx_broadcast_packets", rxbroadcastpackets_g),
	T2H_EQOS_MMC_STAT("rx_multicast_packets", rxmulticastpackets_g),
	T2H_EQOS_MMC_STAT("rx_crc_errors", rxcrcerror),
	T2H_EQOS_MMC_STAT("rx_alignment_errors", rxalignmenterror),
	T2H_EQOS_MMC_STAT("rx_runt_error", rxrunterror),
	T2H_EQOS_MMC_STAT("rx_jabber_error", rxjabbererror),
	T2H_EQOS_MMC_STAT("rx_undersize_packets", rxundersize_g),
	T2H_EQOS_MMC_STAT("rx_oversize_packets", rxoversize_g),
	T2H_EQOS_MMC_STAT("rx_64_byte_packets", rx64octets_gb),
	T2H_EQOS_MMC_STAT("rx_65_to_127_byte_packets", rx65to127octets_gb),
	T2H_EQOS_MMC_STAT("rx_128_to_255_byte_packets", rx128to255octets_gb),
	T2H_EQOS_MMC_STAT("rx_256_to_511_byte_packets", rx256to511octets_gb),
	T2H_EQOS_MMC_STAT("rx_512_to_1023_byte_packets", rx512to1023octets_gb),
	T2H_EQOS_MMC_STAT("rx_1024_to_max_byte_packets", rx1024tomaxoctets_gb),
	T2H_EQOS_MMC_STAT("rx_unicast_packets", rxunicastpackets_g),
	T2H_EQOS_MMC_STAT("rx_length_errors", rxlengtherror),
	T2H_EQOS_MMC_STAT("rx_out_of_range_errors", rxoutofrangetype),
	T2H_EQOS_MMC_STAT("rx_pause_packets", rxpausepackets),
	T2H_EQOS_MMC_STAT("rx_fifo_overflow_errors", rxfifooverflow),
	T2H_EQOS_MMC_STAT("rx_vlan_packets", rxvlanpackets_gb),
	T2H_EQOS_MMC_STAT("rx_watchdog_errors", rxwatchdogerror),

	T2H_EQOS_MMC_STAT("rx_ipc_intr", rxipcintr),

	T2H_EQOS_MMC_STAT("rx_ipv4_gd", rxipv4_gb),
	T2H_EQOS_MMC_STAT("rx_ipv4_hderr", rxipv4_hderr),
	T2H_EQOS_MMC_STAT("rx_ipv4_nopay", rxipv4_nopay),
	T2H_EQOS_MMC_STAT("rx_ipv4_frag", rxipv4_frag),
	T2H_EQOS_MMC_STAT("rx_ipv4_udsbl", rxipv4_udsbl),
	T2H_EQOS_MMC_STAT("rx_ipv4_gd_octets", rxipv4_gb_octets),
	T2H_EQOS_MMC_STAT("rx_ipv4_hderr_octets", rxipv4_hderr_octets),
	T2H_EQOS_MMC_STAT("rx_ipv4_nopay_octets", rxipv4_nopay_octets),
	T2H_EQOS_MMC_STAT("rx_ipv4_frag_octets", rxipv4_frag_octets),
	T2H_EQOS_MMC_STAT("rx_ipv4_udsbl_octets", rxipv4_udsbl_octets),

	T2H_EQOS_MMC_STAT("rx_ipv6_gd_octets", rxipv6_gb_octets),
	T2H_EQOS_MMC_STAT("rx_ipv6_hderr_octets", rxipv6_hderr_octets),
	T2H_EQOS_MMC_STAT("ipv6_nopay_octets", rxipv6_nopay_octets),
	T2H_EQOS_MMC_STAT("rx_ipv6_gd", rxipv6_gb),
	T2H_EQOS_MMC_STAT("rx_ipv6_hderr", rxipv6_hderr),
	T2H_EQOS_MMC_STAT("rx_ipv6_nopay", rxipv6_nopay),

	T2H_EQOS_MMC_STAT("rx_udp_gd", rxudp_gb),
	T2H_EQOS_MMC_STAT("rx_udp_err", rxudp_err),
	T2H_EQOS_MMC_STAT("rx_tcp_gd", rxtcp_gb),
	T2H_EQOS_MMC_STAT("rx_tcp_err", rxtcp_err),
	T2H_EQOS_MMC_STAT("rx_icmp_gd", rxicmp_gb),
	T2H_EQOS_MMC_STAT("rx_icmp_err", rxicmp_err),
	T2H_EQOS_MMC_STAT("rx_udp_gd_octets", rxudp_gb_octets),
	T2H_EQOS_MMC_STAT("udp_err_octets", rxudp_err_octets),
	T2H_EQOS_MMC_STAT("rx_tcp_gd_octets", rxtcp_gb_octets),
	T2H_EQOS_MMC_STAT("rx_tcp_err_octets", rxtcp_err_octets),
	T2H_EQOS_MMC_STAT("rx_icmp_gd_octets", rxicmp_gb_octets),
	T2H_EQOS_MMC_STAT("rx_icmp_err_octets", rxicmp_err_octets),
	T2H_EQOS_MMC_STAT("tx_fpe_fragment_cntr", txfpefragmentcntr),
	T2H_EQOS_MMC_STAT("tx_hold_req_cntr", txholdreqcntr),
	T2H_EQOS_MMC_STAT("rx_packet_assembly_err_cntr", rxpacketassemblyerrcntr),
	T2H_EQOS_MMC_STAT("rx_packet_smd_err_cntr", rxpacketsmderrcntr),
	T2H_EQOS_MMC_STAT("rx_packet_assembly_ok_cntr", rxpacketassemblyokcntr),
	T2H_EQOS_MMC_STAT("rx_fpe_fragment_cntr", rxfpefragmentcntr),
};

#define T2H_EQOS_ARRAY_SIZE(arr)		RTE_DIM(arr)
#define T2H_EQOS_XSTATS_COUNT			T2H_EQOS_ARRAY_SIZE(t2h_eqos_xstats_strings)

#endif /*__T2H_ETHDEV_H__*/
