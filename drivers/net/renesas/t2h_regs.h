/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Renesas Electronics Corporation
 */
#include <rte_ethdev.h>

#ifndef __T2H_REGS_H
#define __T2H_REGS_H

#define BIT(x) ((uint64_t)1 << ((x)))

#define T2H_EQOS_MAC_CONFIG                     0x0000
#define T2H_EQOS_MAC_EXT_CONFIG                 0x0004
#define T2H_EQOS_MAC_PACKET_FILTER              0x0008
#define T2H_EQOS_MAC_HASH_TAB(x)                (0x0010 + (x)*4)
#define T2H_EQOS_MAC_VLAN_TAG                   0x0050
#define T2H_EQOS_MAC_VLAN_TAG_DATA              0x0054
#define T2H_EQOS_MAC_VLAN_HASH_TABLE            0x0058
#define T2H_EQOS_MAC_RXQ_CTRL0                  0x00a0
#define T2H_EQOS_MAC_RXQ_CTRL2                  0x00a8
#define T2H_EQOS_MAC_RXQ_CTRL3                  0x00ac
#define T2H_EQOS_MAC_INT_STATUS                 0x00b0
#define T2H_EQOS_MAC_INT_EN                     0x00b4
#define T2H_EQOS_MAC_LPI_CTRL_STATUS            0x00d0
#define T2J_EQOS_MAC_1US_TIC_COUNTER            0x00dc
#define T2H_EQOS_MAC_VERSION                    0x0110
#define T2H_EQOS_MAC_HW_FEATURE0                0x011c
#define T2H_EQOS_MAC_HW_FEATURE1                0x0120
#define T2H_EQOS_MAC_HW_FEATURE3                0x0128

#define T2H_EQOS_MAC_MDIO_ADDR                  0x0200
#define T2H_EQOS_MAC_MDIO_DATA                  0x0204

#define T2H_EQOS_MAC_ADDR0_HI                   0x0300
#define T2H_EQOS_MAC_ADDR0_LO                   0x0304
#define T2H_EQOS_MAC_ADDR_HI(reg)               (T2H_EQOS_MAC_ADDR0_HI + reg * 8)
#define T2H_EQOS_MAC_ADDR_LO(reg)               (T2H_EQOS_MAC_ADDR0_LO + reg * 8)

#define T2H_EQOS_MAC_TIMESTAMP_CTRL             0x0b00

#define T2H_EQOS_MTL_OPERATION_MODE             0x0c00
#define T2H_EQOS_MTL_RXQ_DMA_MAP0               0x0c30
#define T2H_EQOS_MTL_RXQ_DMA_MAP1               0x0c34
#define T2H_EQOS_MTL_TXQ_WEIGHT_BASE_OFFSET     0x40
#define T2h_EQOS_MTL_RXQ_CONTROL_BASE           0x0d3c
#define T2H_EQOS_MTL_RXQ_CONTROL_BASE_ADDR(x) \
	(T2h_EQOS_MTL_RXQ_CONTROL_BASE + ((x)*T2H_EQOS_MTL_TXQ_WEIGHT_BASE_OFFSET))
#define T2H_EQOS_MTL_RXQ_CONTROL_WEGT_MASK      GENMASK(2, 0)
#define T2H_EQOS_MTL_RXQ_CONTROL_RXQ_FRM_ARBIT  (0x1 << 3)

#define T2H_EQOS_MTL_TXQ_WEIGHT_BASE_ADDR       0x0d18

#define T2H_EQOS_MTL_TXQX_WEIGHT_BASE_ADDR(x) \
	(T2H_EQOS_MTL_TXQ_WEIGHT_BASE_ADDR + ((x)*T2H_EQOS_MTL_TXQ_WEIGHT_BASE_OFFSET))
#define T2H_EQOS_MTL_TXQ_WEIGHT_ISCQW_MASK      GENMASK(20, 0)

#define T2H_EQOS_MAC_RXQCTRL_PSRQX_MASK(x)      GENMASK(7 + ((x)*8), 0 + ((x)*8))
#define T2H_EQOS_MAC_RXQCTRL_PSRQX_SHIFT(x)     ((x)*8)

#define T2H_EQOS_MTL_RXQ_DMA_QXMDMACH_MASK(x)   GENMASK(2 + (8 * (x)), 8 * (x))
#define T2H_EQOS_MTL_RXQ_DMA_QXMDMACH(chan, q)  ((chan) << (8 * (q)))

#define T2H_EQOS_MTL_OPERATION_RAA              BIT(2)
#define T2H_EQOS_MTL_OPERATION_RAA_WSP          (0x1 << 2)
#define T2H_EQOS_MTL_OPERATION_SCHALG_WRR       (0x0 << 5)
#define T2H_EQOS_MTL_OPERATION_SCHALG_MASK      GENMASK(6, 5)

#define T2H_EQOS_MMC_CNTRL                      0x0700
#define T2H_EQOS_MMC_RX_INTR_MASK               0x070c
#define T2H_EQOS_MMC_TX_INTR_MASK               0x0710

#define T2H_EQOS_MMC_TX_OCTETCOUNT_GB           0x0714
#define T2H_EQOS_MMC_TX_FRAMECOUNT_GB           0x0718
#define T2H_EQOS_MMC_TX_BROADCASTFRAME_G        0x071c
#define T2H_EQOS_MMC_TX_MULTICASTFRAME_G        0x0720
#define T2H_EQOS_MMC_TX_64_OCTETS_GB            0x0724
#define T2H_EQOS_MMC_TX_65_TO_127_OCTETS_GB     0x0728
#define T2H_EQOS_MMC_TX_128_TO_255_OCTETS_GB    0x072c
#define T2H_EQOS_MMC_TX_256_TO_511_OCTETS_GB    0x0730
#define T2H_EQOS_MMC_TX_512_TO_1023_OCTETS_GB   0x0734
#define T2H_EQOS_MMC_TX_1024_TO_MAX_OCTETS_GB   0x0738
#define T2H_EQOS_MMC_TX_UNICAST_GB              0x073c
#define T2H_EQOS_MMC_TX_MULTICAST_GB            0x0740
#define T2H_EQOS_MMC_TX_BROADCAST_GB            0x0744
#define T2H_EQOS_MMC_TX_UNDERFLOW_ERROR         0x0748
#define T2H_EQOS_MMC_TX_SINGLECOL_G             0x074c
#define T2H_EQOS_MMC_TX_MULTICOL_G              0x0750
#define T2H_EQOS_MMC_TX_DEFERRED                0x0754
#define T2H_EQOS_MMC_TX_LATECOL                 0x0758
#define T2H_EQOS_MMC_TX_EXESSCOL                0x075c
#define T2H_EQOS_MMC_TX_CARRIER_ERROR           0x0760
#define T2H_EQOS_MMC_TX_OCTETCOUNT_G            0x0764
#define T2H_EQOS_MMC_TX_FRAMECOUNT_G            0x0768
#define T2H_EQOS_MMC_TX_EXCESSDEF               0x076c
#define T2H_EQOS_MMC_TX_PAUSE_FRAME             0x0770
#define T2H_EQOS_MMC_TX_VLAN_FRAME_G            0x0774

#define T2H_EQOS_MMC_RX_FRAMECOUNT_GB           0x0780
#define T2H_EQOS_MMC_RX_OCTETCOUNT_GB           0x0784
#define T2H_EQOS_MMC_RX_OCTETCOUNT_G            0x0788
#define T2H_EQOS_MMC_RX_BROADCASTFRAME_G        0x078c
#define T2H_EQOS_MMC_RX_MULTICASTFRAME_G        0x0790
#define T2H_EQOS_MMC_RX_CRC_ERROR               0x0794
#define T2H_EQOS_MMC_RX_ALIGN_ERROR             0x0798
#define T2H_EQOS_MMC_RX_RUN_ERROR               0x079c
#define T2H_EQOS_MMC_RX_JABBER_ERROR            0x07A0
#define T2H_EQOS_MMC_RX_UNDERSIZE_G             0x07A4
#define T2H_EQOS_MMC_RX_OVERSIZE_G              0x07A8
#define T2H_EQOS_MMC_RX_64_OCTETS_GB            0x07AC
#define T2H_EQOS_MMC_RX_65_TO_127_OCTETS_GB     0x07B0
#define T2H_EQOS_MMC_RX_128_TO_255_OCTETS_GB    0x07B4
#define T2H_EQOS_MMC_RX_256_TO_511_OCTETS_GB    0x07B8
#define T2H_EQOS_MMC_RX_512_TO_1023_OCTETS_GB   0x07BC
#define T2H_EQOS_MMC_RX_1024_TO_MAX_OCTETS_GB   0x07C0
#define T2H_EQOS_MMC_RX_UNICAST_G               0x07C4
#define T2H_EQOS_MMC_RX_LENGTH_ERROR            0x07C8
#define T2H_EQOS_MMC_RX_AUTOFRANGETYPE          0x07CC
#define T2H_EQOS_MMC_RX_PAUSE_FRAMES            0x07D0
#define T2H_EQOS_MMC_RX_FIFO_OVERFLOW           0x07D4
#define T2H_EQOS_MMC_RX_VLAN_FRAMES_GB          0x07D8
#define T2H_EQOS_MMC_RX_WATCHDOG_ERROR          0x07DC

#define T2H_EQOS_MMC_RX_IPC_INTR_MASK           0x0800
#define T2H_EQOS_MMC_RX_IPC_INTR                0x0808

#define T2H_EQOS_MMC_RX_IPV4_GD                 0x0810
#define T2H_EQOS_MMC_RX_IPV4_HDERR              0x0814
#define T2H_EQOS_MMC_RX_IPV4_NOPAY              0x0818
#define T2H_EQOS_MMC_RX_IPV4_FRAG               0x081C
#define T2H_EQOS_MMC_RX_IPV4_UDSBL              0x0820
#define T2H_EQOS_MMC_RX_IPV4_GD_OCTETS          0x0850
#define T2H_EQOS_MMC_RX_IPV4_HDERR_OCTETS       0x0854
#define T2H_EQOS_MMC_RX_IPV4_NOPAY_OCTETS       0x0858
#define T2H_EQOS_MMC_RX_IPV4_FRAG_OCTETS        0x085C
#define T2H_EQOS_MMC_RX_IPV4_UDSBL_OCTETS       0x0860

#define T2H_EQOS_MMC_RX_IPV6_GD_OCTETS          0x0864
#define T2H_EQOS_MMC_RX_IPV6_HDERR_OCTETS       0x0868
#define T2H_EQOS_MMC_RX_IPV6_NOPAY_OCTETS       0x086C
#define T2H_EQOS_MMC_RX_IPV6_GD                 0x0824
#define T2H_EQOS_MMC_RX_IPV6_HDERR              0x0828
#define T2H_EQOS_MMC_RX_IPV6_NOPAY              0x082C

#define T2H_EQOS_MMC_RX_UDP_GD                  0x0830
#define T2H_EQOS_MMC_RX_UDP_ERR                 0x0834
#define T2H_EQOS_MMC_RX_TCP_GD                  0x0838
#define T2H_EQOS_MMC_RX_TCP_ERR                 0x083C
#define T2H_EQOS_MMC_RX_ICMP_GD                 0x0840
#define T2H_EQOS_MMC_RX_ICMP_ERR                0x0844
#define T2H_EQOS_MMC_RX_UDP_GD_OCTETS           0x0870
#define T2H_EQOS_MMC_RX_UDP_ERR_OCTETS          0x0874
#define T2H_EQOS_MMC_RX_TCP_GD_OCTETS           0x0878
#define T2H_EQOS_MMC_RX_TCP_ERR_OCTETS          0x087C
#define T2H_EQOS_MMC_RX_ICMP_GD_OCTETS          0x0880
#define T2H_EQOS_MMC_RX_ICMP_ERR_OCTETS         0x0884
#define T2H_EQOS_MMC_TX_FPE_FRAG                0x08A8
#define T2H_EQOS_MMC_TX_HOLD_REQ                0x08AC
#define T2H_EQOS_MMC_RX_PKT_ASSEMBLY_ERR        0x08C8
#define T2H_EQOS_MMC_RX_PKT_SMD_ERR             0x08CC
#define T2H_EQOS_MMC_RX_PKT_ASSEMBLY_OK         0x08D0
#define T2H_EQOS_MMC_RX_FPE_FRAG                0x08D4

#define T2H_EQOS_PHY_BMCR                       0x0000
#define T2H_EQOS_PHY_AUTO_NEG                   0x0004
#define T2H_EQOS_PHY_1000BASE_T                 0x0009

#define T2H_EQOS_MAC_CONFIG_IPC                 BIT(27)
#define T2H_EQOS_MAC_CONFIG_CST                 BIT(21)
#define T2H_EQOS_MAC_CONFIG_BE                  BIT(18)
#define T2H_EQOS_MAC_CONFIG_JD                  BIT(17)
#define T2H_EQOS_MAC_CONFIG_JE                  BIT(16)
#define T2H_EQOS_MAC_CONFIG_PS                  BIT(15)
#define T2H_EQOS_MAC_CONFIG_FES                 BIT(14)
#define T2H_EQOS_MAC_CONFIG_DM                  BIT(13)
#define T2H_EQOS_MAC_CONFIG_DCRS                BIT(9)
#define T2H_EQOS_MAC_CONFIG_TE                  BIT(1)
#define T2H_EQOS_MAC_CONFIG_RE                  BIT(0)

#define T2H_EQOS_MAC_CONFIG_HDSMS               GENMASK(22, 20)
#define T2H_EQOS_MAC_CONFIG_HDSMS_SHIFT         20
#define T2H_EQOS_MAC_CONFIG_HDSMS_256           (0x2 << T2H_EQOS_MAC_CONFIG_HDSMS_SHIFT)

#define T2H_EQOS_MAC_PACKET_FILTER_VTFE         BIT(16)
#define T2H_EQOS_MAC_PACKET_FILTER_PM           BIT(4)
#define T2H_EQOS_MAC_PACKET_FILTER_PR           BIT(0)

#define T2H_EQOS_MAC_VLAN_TAG_EDVLP             BIT(26)
#define T2H_EQOS_MAC_VLAN_TAG_VTHM              BIT(25)
#define T2H_EQOS_MAC_VLAN_TAG_DOVLTC            BIT(20)
#define T2H_EQOS_MAC_VLAN_TAG_ESVL              BIT(18)
#define T2H_EQOS_MAC_VLAN_TAG_ETV               BIT(16)
#define T2H_EQOS_MAC_VLAN_TAG_VID               GENMASK(15, 0)
#define T2H_EQOS_MAC_VLAN_TAG_CT                BIT(1)
#define T2H_EQOS_MAC_VLAN_TAG_OB                BIT(0)

#define T2H_EQOS_MAC_VLAN_VLHT                  GENMASK(15, 0)

#define T2H_EQOS_MAC_VLAN_TAG_OFS_MASK          GENMASK(6, 2)
#define T2H_EQOS_MAC_VLAN_TAG_OFS_SHIFT         2

#define T2H_EQOS_MAC_VLAN_TAG_DATA_ETV          BIT(17)
#define T2H_EQOS_MAC_VLAN_TAG_DATA_VEN          BIT(16)
#define T2H_EQOS_MAC_VLAN_TAG_DATA_VID          GENMASK(15, 0)

#define T2H_EQOS_MAC_LPI_CTRL_STATUS_PLS        BIT(17)

#define T2H_EQOS_MAC_HW_FEAT0_VLHASH            BIT(4)

#define T2H_EQOS_MAC_HW_FEAT1_HASH_TB_SZ        GENMASK(25, 24)
#define T2H_EQOS_MAC_HW_FEAT1_TXFIFOSIZE        GENMASK(10, 6)
#define T2H_EQOS_MAC_HW_FEAT1_RXFIFOSIZE        GENMASK(4, 0)

#define T2H_EQOS_MAC_HW_FEAT3_NRVF              GENMASK(2, 0)

#define T2H_EQOS_MAC_DEFINED_VERSION            GENMASK(7, 0)

#define T2H_EQOS_MAC_ADDR0_HI_AE                BIT(31)

#define T2H_EQOS_PTP_TCR_TSENA                  BIT(0)

#define T2H_EQOS_DMA_BUS_MODE                   0x1000
#define T2H_EQOS_DMA_SYS_BUS_MODE               0x1004
#define T2H_EQOS_DMA_TBS_CTRL                   0x1050

#define T2H_EQOS_DMA_CH_BASE_ADDR               0x1100
#define T2H_EQOS_DMA_CH_BASE_OFFSET             0x0080
#define T2H_EQOS_DMA_CHX_BASE_ADDR(CH) \
	(T2H_EQOS_DMA_CH_BASE_ADDR + (CH * T2H_EQOS_DMA_CH_BASE_OFFSET))
#define T2H_EQOS_DMA_CH_CTRL(CH)                T2H_EQOS_DMA_CHX_BASE_ADDR(CH)
#define T2H_EQOS_DMA_CH_TX_CTRL(CH)             (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0004)
#define T2H_EQOS_DMA_CH_RX_CTRL(CH)             (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0008)
#define T2H_EQOS_DMA_CH_TX_BASE_ADDR(CH)        (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0014)
#define T2H_EQOS_DMA_CH_RX_BASE_ADDR(CH)        (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x001c)
#define T2H_EQOS_DMA_CH_TX_END_ADDR(CH)         (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0020)
#define T2H_EQOS_DMA_CH_RX_END_ADDR(CH)         (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0028)
#define T2H_EQOS_DMA_CH_TX_RING_LEN(CH)         (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x002c)
#define T2H_EQOS_DMA_CH_RX_RING_LEN(CH)         (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0030)
#define T2H_EQOS_DMA_CH_INTR_ENA(CH)            (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0034)
#define T2H_EQOS_DMA_CH_RX_WATCHDOG(CH)         (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0038)
#define T2H_EQOS_DMA_CH_SLOT_CTRL_STATUS(CH)    (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x003c)
#define T2H_EQOS_DMA_CH_CUR_TX_DESC(CH)         (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0044)
#define T2H_EQOS_DMA_CH_CUR_RX_DESC(CH)         (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x004c)
#define T2H_EQOS_DMA_CH_CUR_TX_BUF_ADDR(CH)     (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0054)
#define T2H_EQOS_DMA_CH_CUR_RX_BUF_ADDR(CH)     (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x005c)
#define T2H_EQOS_DMA_CH_STATUS(CH)              (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0060)
#define T2H_EQOS_DMA_CH_MISS_FRAME_CNT(CH)      (T2H_EQOS_DMA_CHX_BASE_ADDR(CH) + 0x0064)

#define T2H_EQOS_DMA_RBSZ_MASK                  GENMASK(14, 1)
#define T2H_EQOS_DMA_RBSZ_SHIFT                 1

#define T2H_EQOS_DMA_BUS_MODE_TAA               GENMASK(4, 2)
#define T2H_EQOS_DMA_BUS_MODE_TAA_SHIFT         2
#define T2H_EQOS_DMA_BUS_MODE_SWR               BIT(0)

#define T2H_EQOS_DMA_AXI_WR_OSR_LMT_SHIFT       24
#define T2H_EQOS_DMA_AXI_RD_OSR_LMT_SHIFT       16

#define T2H_EQOS_DMA_SYS_BUS_AAL                BIT(12)
#define T2H_EQOS_DMA_AXI_BLEN16                 BIT(3)
#define T2H_EQOS_DMA_AXI_BLEN8                  BIT(2)
#define T2H_EQOS_DMA_AXI_BLEN4                  BIT(1)

#define T2H_EQOS_DMA_TBS_FGOS                   GENMASK(6, 4)
#define T2H_EQOS_DMA_TBS_DEF_FTOS               (T2H_EQOS_DMA_TBS_FGOS)

#define T2H_EQOS_DMA_CH_CTRL_SPH                BIT(24)

#define T2H_EQOS_DMA_CH_TX_CTRL_EDSE            BIT(28)
#define T2H_EQOS_DMA_CH_TX_CTRL_OSP             BIT(4)
#define T2H_EQOS_DMA_CH_TX_CTRL_ST              BIT(0)

#define T2H_EQOS_DMA_CH_RX_CTRL_SR              BIT(0)

#define T2H_EQOS_DMA_CH_INTR_ENA_NO_INTRS       (0)

#define T2H_EQOS_MTL_CHAN_BASE_ADDR             0x0d00
#define T2H_EQOS_MTL_CHAN_BASE_OFFSET           0x40
#define T2H_EQOS_MTL_CHANX_BASE_ADDR(x) \
	(T2H_EQOS_MTL_CHAN_BASE_ADDR + (x * T2H_EQOS_MTL_CHAN_BASE_OFFSET))
#define T2H_EQOS_MTL_CHAN_TX_OP_MODE(x)         T2H_EQOS_MTL_CHANX_BASE_ADDR(x)
#define T2H_EQOS_MTL_CHAN_RX_OP_MODE(x)         (T2H_EQOS_MTL_CHANX_BASE_ADDR(x) + 0x30)
#define T2H_EQOS_MTL_OP_MODE_RSF                BIT(5)
#define T2H_EQOS_MTL_OP_MODE_TXQEN              BIT(3)
#define T2H_EQOS_MTL_OP_MODE_TSF                BIT(1)
#define T2H_EQOS_MTL_OP_MODE_RQS_MASK           GENMASK(29, 20)
#define T2H_EQOS_MTL_OP_MODE_TQS_MASK           GENMASK(24, 16)
#define T2H_EQOS_MTL_OP_MODE_RFD_MASK           GENMASK(19, 14)
#define T2H_EQOS_MTL_OP_MODE_RFA_MASK           GENMASK(13, 8)
#define T2H_EQOS_MTL_OP_MODE_TXQEN_MASK         GENMASK(3, 2)
#define T2H_EQOS_MTL_OP_MODE_RQS_SHIFT          20
#define T2H_EQOS_MTL_OP_MODE_TQS_SHIFT          16
#define T2H_EQOS_MTL_OP_MODE_RFD_SHIFT          14
#define T2H_EQOS_MTL_OP_MODE_RFA_SHIFT          8

#define T2H_EQOS_MMC_CNTRL_COUNTER_RESET        0x1

#define T2H_EQOS_MMC_CNTRL_RESET_ON_READ        0x4
#define T2H_EQOS_MMC_CNTRL_PRESET               0x10
#define T2H_EQOS_MMC_CNTRL_FULL_HALF_PRESET     0x20

#define T2H_EQOS_MMC_RXTX_DEFAULT_MASK          0xfffffff
#define T2H_EQOS_MMC_DEFAULT_MASK               0x3fff3fff

#define T2H_EQOS_RXQ_CTL2_PSRQ1_SHIFT           8
#define T2H_EQOS_RXQ_CTL2_PSRQ2_SHIFT           16
#define T2H_EQOS_RXQ_CTL2_PSRQ3_SHIFT           24
#define T2H_EQOS_RXQ_CTL3_PSRQ5_SHIFT           8
#define T2H_EQOS_RXQ_CTL3_PSRQ6_SHIFT           16
#define T2H_EQOS_RXQ_CTL3_PSRQ7_SHIFT           24

#define T2H_EQOS_MDIO_ADDR_GOC_SHIFT            2
#define T2H_EQOS_MDIO_ADDR_CSR_SHIFT            8
#define T2H_EQOS_MDIO_ADDR_REG_SHIFT            16
#define T2H_EQOS_MDIO_ADDR_PA_SHIFT             21
#define T2H_EQOS_MDIO_ADDR_GOC_WRITE            (1 << T2H_EQOS_MDIO_ADDR_GOC_SHIFT)
#define T2H_EQOS_MDIO_ADDR_GOC_READ             (3 << T2H_EQOS_MDIO_ADDR_GOC_SHIFT)
#define T2H_EQOS_MDIO_ADDR_CSR_MASK             GENMASK(11, 8)
#define T2H_EQOS_MDIO_ADDR_REG_MASK             GENMASK(20, 16)
#define T2H_EQOS_MDIO_ADDR_PA_MASK              GENMASK(25, 21)
#define T2H_EQOS_MDIO_DATA_GD_MASK              GENMASK(15, 0)

#define T2H_EQOS_MDIO_ADDR_BUSY                 BIT(0)

#define T2H_EQOS_PHY_BMCR_AUTONEG               BIT(12)
#define T2H_EQOS_PHY_BMCR_RESTART_AUTONEG       BIT(9)

#define T2H_EQOS_PHY_AUTO_NEG_100_FULL          BIT(8)
#define T2H_EQOS_PHY_AUTO_NEG_100_HALF          BIT(7)
#define T2H_EQOS_PHY_AUTO_NEG_10_FULL           BIT(6)
#define T2H_EQOS_PHY_AUTO_NEG_10_HALF           BIT(5)

#define T2H_EQOS_PHY_1000BASE_T_FULL            BIT(9)
#define T2H_EQOS_PHY_1000BASE_T_HALF            BIT(8)

#endif /* __T2H_REGS_H */
