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
};

#endif /*__T2H_ETHDEV_H__*/
