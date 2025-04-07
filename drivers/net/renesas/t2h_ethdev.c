/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Renesas Electronics Corporation
 */

#include <inttypes.h>
#include <ethdev_vdev.h>
#include <ethdev_driver.h>
#include <rte_io.h>
#include <unistd.h>

#include "t2h_pmd_logs.h"
#include "t2h_ethdev.h"
#include "t2h_regs.h"
#include "t2h_uio.h"
#include "t2h_rxtx.h"
#include "t2h_util.h"

#define T2H_EQOS_NAME_PMD	  net_renesas
#define T2H_EQOS_MAX_ADDR	  (31)
#define T2H_EQOS_NUM_OF_BD_QUEUES (16)

#define T2H_EQOS_AXI_WR_OSR_LMT (0x0E)
#define T2H_EQOS_AXI_RD_OSR_LMT (0x0E)

static uint64_t dev_rx_offloads_sup =
	RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_VLAN_FILTER | RTE_ETH_RX_OFFLOAD_KEEP_CRC;

static int
t2h_eqos_set_mac_addr(struct rte_eth_dev *dev, struct rte_ether_addr *addr)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	uint32_t data;

	if (!addr) {
		T2H_EQOS_PMD_ERR("mac address is NULL");
		return -EINVAL;
	}

	data = (addr->addr_bytes[5] << T2H_EQOS_MAC_HIGH_EIGHT) | addr->addr_bytes[4];
	data |= (T2H_EQOS_CHAN0 << T2H_EQOS_MAC_HI_DCS_SHIFT);
	rte_write32(rte_cpu_to_le_32(data | T2H_EQOS_MAC_ADDR0_HI_AE),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_ADDR0_HI);

	data = addr->addr_bytes[3] << T2H_EQOS_MAC_LOW_TWENTY_FOUR |
	       (addr->addr_bytes[2] << T2H_EQOS_MAC_LOW_SIXTEEN) |
	       (addr->addr_bytes[1] << T2H_EQOS_MAC_LOW_EIGHT) | (addr->addr_bytes[0]);
	rte_write32(rte_cpu_to_le_32(data), (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_ADDR0_LO);

	rte_ether_addr_copy(addr, &dev->data->mac_addrs[0]);

	return 0;
}

static void
t2h_eqos_get_mac_addr(struct renesas_t2h_private *priv, struct rte_ether_addr *addr)
{
	uint32_t mac_addr_hi = 0, mac_addr_lo = 0;

	mac_addr_hi = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_ADDR0_HI));
	mac_addr_lo = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_ADDR0_LO));

	/* Write the MAC address to addr_bytes */
	addr->addr_bytes[0] = mac_addr_lo & T2H_EQOS_FULL_MASK;
	addr->addr_bytes[1] = (mac_addr_lo >> T2H_EQOS_MAC_LOW_EIGHT) & T2H_EQOS_FULL_MASK;
	addr->addr_bytes[2] = (mac_addr_lo >> T2H_EQOS_MAC_LOW_SIXTEEN) & T2H_EQOS_FULL_MASK;
	addr->addr_bytes[3] = (mac_addr_lo >> T2H_EQOS_MAC_LOW_TWENTY_FOUR) & T2H_EQOS_FULL_MASK;
	addr->addr_bytes[4] = mac_addr_hi & T2H_EQOS_FULL_MASK;
	addr->addr_bytes[5] = (mac_addr_hi >> T2H_EQOS_MAC_HIGH_EIGHT) & T2H_EQOS_FULL_MASK;
}

static void
t2h_eqos_set_mac_addn_addr(struct renesas_t2h_private *priv, uint8_t *addr, uint32_t index)
{
	uint32_t mac_addr_hi = 0, mac_addr_lo = 0;

	if (addr) {
		mac_addr_lo = addr[3] << T2H_EQOS_MAC_LOW_TWENTY_FOUR |
			      (addr[2] << T2H_EQOS_MAC_LOW_SIXTEEN) |
			      (addr[1] << T2H_EQOS_MAC_LOW_EIGHT) | (addr[0]);

		mac_addr_hi = (addr[5] << T2H_EQOS_MAC_HIGH_EIGHT) | addr[4];
		mac_addr_hi |= (T2H_EQOS_CHAN0 << T2H_EQOS_MAC_HI_DCS_SHIFT);
		mac_addr_hi |= T2H_EQOS_MAC_ADDR0_HI;
	}

	T2H_EQOS_PMD_INFO("%s mac address at %#x", addr ? "set" : "clear", index);

	rte_write32(rte_cpu_to_le_32(mac_addr_hi),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_ADDR_HI(index));
	rte_write32(rte_cpu_to_le_32(mac_addr_lo),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_ADDR_LO(index));
}

static int
t2h_eqos_add_mac_addr(struct rte_eth_dev *dev, struct rte_ether_addr *mac_addr, uint32_t index,
		      uint32_t pool __rte_unused)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;

	if (index > T2H_EQOS_MAX_ADDR) {
		T2H_EQOS_PMD_ERR("Invalid Index %d", index);
		return -EINVAL;
	}

	t2h_eqos_set_mac_addn_addr(priv, (uint8_t *)mac_addr, index);
	rte_ether_addr_copy(mac_addr, &dev->data->mac_addrs[index]);

	return 0;
}

static void
t2h_eqos_remove_mac_addr(struct rte_eth_dev *dev, uint32_t index)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;

	if (index > T2H_EQOS_MAX_ADDR) {
		T2H_EQOS_PMD_ERR("Invalid Index %d", index);
		return;
	}

	t2h_eqos_set_mac_addn_addr(priv, NULL, index);
	memset(&dev->data->mac_addrs[index], 0, sizeof(struct rte_ether_addr));
}

static int
t2h_eqos_set_mc_addr_list(struct rte_eth_dev *dev, struct rte_ether_addr *mac_addr_list,
			  uint32_t nb_mac_addr)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	uint32_t index			 = 0;
	struct rte_ether_addr *addr;

	if (nb_mac_addr > T2H_EQOS_MAX_ADDR) {
		T2H_EQOS_PMD_ERR("Invalid Index %d", nb_mac_addr);
		return -EINVAL;
	}

	/* Validate the given addresses first */
	for (index = 0; index < nb_mac_addr && mac_addr_list != NULL; index++) {
		addr = &mac_addr_list[index];
		if (!rte_is_multicast_ether_addr(addr) || rte_is_broadcast_ether_addr(addr)) {
			char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
			rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, addr);
			T2H_EQOS_PMD_ERR(" invalid multicast address %s", mac_str);
			return -EINVAL;
		}
	}

	/* clear addresses */
	for (index = 1; index < T2H_EQOS_MAX_ADDR; index++) {
		if (nb_mac_addr) {
			t2h_eqos_set_mac_addn_addr(priv, (uint8_t *)mac_addr_list, index);
			rte_ether_addr_copy(mac_addr_list, &dev->data->mac_addrs[index]);
			mac_addr_list++;
			nb_mac_addr--;
		} else {
			if (rte_is_zero_ether_addr(&dev->data->mac_addrs[index]))
				continue;
			t2h_eqos_set_mac_addn_addr(priv, NULL, index);
			memset(&dev->data->mac_addrs[index], 0, sizeof(struct rte_ether_addr));
		}
	}

	return 0;
}

static void
t2h_eqos_set_mac(struct renesas_t2h_private *priv, bool enable)
{
	uint32_t value =
		rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG));
	if (enable)
		value |= T2H_EQOS_MAC_CONFIG_RE | T2H_EQOS_MAC_CONFIG_TE;
	else
		value &= ~(T2H_EQOS_MAC_CONFIG_RE | T2H_EQOS_MAC_CONFIG_TE);
	rte_write32(rte_cpu_to_le_32(value), (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG);
}

static int
t2h_eqos_eth_link_update(struct rte_eth_dev *dev, int wait_to_complete __rte_unused)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	struct rte_eth_link link;

	memset(&link, 0, sizeof(struct rte_eth_link));
	/* get the link status before link update, for predicting later */
	rte_eth_linkstatus_get(dev, &link);

	uint32_t lpi_ctrl_status = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_LPI_CTRL_STATUS));

	uint32_t value =
		rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG));
	if (value & T2H_EQOS_MAC_CONFIG_PS) {
		if (value & T2H_EQOS_MAC_CONFIG_FES) {
			link.link_speed = RTE_ETH_SPEED_NUM_100M;
		} else {
			link.link_speed = RTE_ETH_SPEED_NUM_10M;
		}
	} else {
		if (!(value & T2H_EQOS_MAC_CONFIG_FES)) {
			link.link_speed = RTE_ETH_SPEED_NUM_1G;
		} else {
			T2H_EQOS_PMD_ERR("Speed Set Error");
		}
	}

	if (value & T2H_EQOS_MAC_CONFIG_DM) {
		link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	} else {
		link.link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
	}

	if (lpi_ctrl_status & T2H_EQOS_MAC_LPI_CTRL_STATUS_PLS) {
		T2H_EQOS_PMD_INFO("RTE_ETH_LINK_UP");
		link.link_status = RTE_ETH_LINK_UP;
	} else {
		T2H_EQOS_PMD_INFO("RTE_ETH_LINK_DOWN");
		link.link_status = RTE_ETH_LINK_DOWN;
	}

	rte_eth_linkstatus_set(dev, &link);

	return 0;
}

static void
t2h_eqos_dev_intr_handler(void *param)
{
	struct rte_eth_dev *dev		 = (struct rte_eth_dev *)param;
	struct renesas_t2h_private *priv = dev->data->dev_private;
	struct rte_intr_handle *intr_handle;

	intr_handle = dev->intr_handle;

	if (rte_intr_fd_get(intr_handle) < 0) {
		T2H_EQOS_PMD_ERR("Failed to get intr handle");
		return;
	}

	uint32_t dma_intr_status = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_STATUS(0)));

	uint32_t dma_intr_en = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_INTR_ENA(0)));

	rte_write32(rte_cpu_to_le_32(dma_intr_status & dma_intr_en),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_STATUS(0));

	if (dev->data->dev_conf.intr_conf.lsc != 0) {
		t2h_eqos_eth_link_update(dev, 0);
		rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC, NULL);
	}

	rte_intr_ack(intr_handle);
}

static int
t2h_eqos_eth_configure(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;

	if ((dev->data->dev_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_CHECKSUM) ||
	    (dev->data->dev_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM) ||
	    ((dev->data->dev_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_UDP_CKSUM) ||
	     (dev->data->dev_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_TCP_CKSUM))) {
		priv->flag_csum |= T2H_EQOS_MAC_CONFIG_IPC;
	} else {
		priv->flag_csum &= ~T2H_EQOS_MAC_CONFIG_IPC;
	}

	if (dev->data->dev_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC) {
		priv->flag_csum &= ~T2H_EQOS_MAC_CONFIG_CST;
	} else {
		priv->flag_csum |= T2H_EQOS_MAC_CONFIG_CST;
	}
	T2H_EQOS_PMD_DEBUG("flag_csum = 0x%x", priv->flag_csum);

	return 0;
}

static int
t2h_eqos_eth_info(__rte_unused struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	dev_info->speed_capa = RTE_ETH_LINK_SPEED_10M;
	dev_info->speed_capa |= RTE_ETH_LINK_SPEED_100M;
	dev_info->speed_capa |= RTE_ETH_LINK_SPEED_1G;

	dev_info->max_rx_pktlen	  = T2H_EQOS_MAX_RX_PKT_LEN;
	dev_info->max_rx_queues	  = T2H_EQOS_MAX_Q;
	dev_info->max_tx_queues	  = T2H_EQOS_MAX_Q;
	dev_info->rx_offload_capa = dev_rx_offloads_sup;
	dev_info->max_mac_addrs	  = T2H_EQOS_MAX_MAC_ADDR;

	dev_info->min_mtu = T2H_EQOS_ZLEN - T2H_EQOS_HLEN;
	dev_info->max_mtu = T2H_EQOS_JUMBO_LEN;

	return 0;
}

static int
t2h_eqos_dma_reset(struct renesas_t2h_private *priv)
{
	uint32_t value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_BUS_MODE));
	T2H_EQOS_PMD_DEBUG("DMA Mode is 0x%x", value);

	value |= T2H_EQOS_DMA_BUS_MODE_SWR;

	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_BUS_MODE);

	/* Wait (at most) 1 seconds for DMA reset */
	uint8_t try_counter = T2H_EQOS_DMA_RESET_TRY_COUNT;
	while (try_counter) {
		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_BUS_MODE));
		if (!(value & T2H_EQOS_DMA_BUS_MODE_SWR))
			break;
		try_counter--;
		T2H_EQOS_UDELAY(T2H_EQOS_DMA_RESET_DELAY_TIME);
	}

	if (0 == try_counter) {
		T2H_EQOS_PMD_WARN("DMA_Mode: the reset operation is not complete");
		return -1;
	}

	value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_BUS_MODE));
	value &= ~T2H_EQOS_DMA_BUS_MODE_TAA;
	value |= 2 << T2H_EQOS_DMA_BUS_MODE_TAA_SHIFT;
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_BUS_MODE);
	T2H_EQOS_PMD_DEBUG("DMA reset complete, DMA Mode is 0x%x", value);
	return 0;
}

static void
t2h_eqos_dma_init(struct renesas_t2h_private *priv)
{
	uint32_t value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_SYS_BUS_MODE));
	T2H_EQOS_PMD_DEBUG("System Bus Mode is 0x%x", value);

	value |= T2H_EQOS_DMA_SYS_BUS_AAL;
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_SYS_BUS_MODE);
}

static void
t2h_eqos_core_init(struct renesas_t2h_private *priv)
{
	uint32_t value =
		rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG));
	value |= T2H_EQOS_MAC_CORE_INIT;
	value |= T2H_EQOS_MAC_CONFIG_TE;
#if DEFAULT_SPEED == T2H_EQOS_SPEED_100
	T2H_EQOS_PMD_DEBUG("Current speed is 100 ");
	value |= T2H_EQOS_MAC_CONFIG_FES | T2H_EQOS_MAC_CONFIG_PS;
#elif DEFAULT_SPEED == T2H_EQOS_SPEED_10
	T2H_EQOS_PMD_DEBUG("Current speed is 10 ");
	value |= T2H_EQOS_MAC_CONFIG_PS;
#else
	T2H_EQOS_PMD_DEBUG("Current speed is 1000 ");
#endif

	value |= T2H_EQOS_MAC_CONFIG_DM;
	T2H_EQOS_PMD_DEBUG("value = 0x%x flag_csum = 0x%x", value, priv->flag_csum);
	value |= priv->flag_csum;
	rte_write32(rte_cpu_to_le_32(value), (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG);
}

static void
t2h_eqos_mtl_rx_algorithms(struct renesas_t2h_private *priv)
{
	uint32_t value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MTL_OPERATION_MODE));
	value &= ~T2H_EQOS_MTL_OPERATION_RAA;
	value |= T2H_EQOS_MTL_OPERATION_RAA_WSP;
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MTL_OPERATION_MODE);
}

static void
t2h_eqos_mtl_tx_algorithms(struct renesas_t2h_private *priv)
{
	uint32_t value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MTL_OPERATION_MODE));
	value &= ~T2H_EQOS_MTL_OPERATION_SCHALG_MASK;
	value |= T2H_EQOS_MTL_OPERATION_SCHALG_WRR;
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MTL_OPERATION_MODE);
}

static void
t2h_eqos_rx_queue_dma_chan_map(struct renesas_t2h_private *priv, uint32_t queue)
{
	uint32_t value;

	if (queue < T2H_EQOS_QUEUE_REG_OTH) {
		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MTL_RXQ_DMA_MAP0));
		value &= ~T2H_EQOS_MTL_RXQ_DMA_QXMDMACH_MASK(queue);
		value |= T2H_EQOS_MTL_RXQ_DMA_QXMDMACH(queue, queue);
		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MTL_RXQ_DMA_MAP0);
	} else {
		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MTL_RXQ_DMA_MAP1));
		value &= ~T2H_EQOS_MTL_RXQ_DMA_QXMDMACH_MASK(queue - T2H_EQOS_QUEUE_REG_OTH);
		value |= T2H_EQOS_MTL_RXQ_DMA_QXMDMACH(queue, queue - T2H_EQOS_QUEUE_REG_OTH);
		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MTL_RXQ_DMA_MAP1);
	}
}

static void
t2h_eqos_rx_queue_priority(struct renesas_t2h_private *priv)
{
	uint32_t priority;
	uint32_t value = 0, value2 = 0;

	switch (priv->rx_queues_to_use) {
	case T2H_EQOS_QUEUE_NUM_TWO:
		/* Assign vlan tag 0\1\6\7 to queue 0.*/
		value = T2H_EQOS_TWO_QUEUE_Q_0;
		/* Assign vlan tag 2\3\4\5 to queue 1 */
		value |= T2H_EQOS_TWO_QUEUE_Q_1 << T2H_EQOS_RXQ_CTL2_PSRQ1_SHIFT;

		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL2);
		break;
	case T2H_EQOS_QUEUE_NUM_THREE:
		/* Assign vlan tag  0\7 to queue 0. */
		value = T2H_EQOS_THREE_QUEUE_Q_0;
		/* Assign vlan tag 1\2\6 to queue 1. */
		value |= T2H_EQOS_THREE_QUEUE_Q_1 << T2H_EQOS_RXQ_CTL2_PSRQ1_SHIFT;
		/* Assign vlan tag 3\4\5 to queue 2 */
		value |= T2H_EQOS_THREE_QUEUE_Q_2 << T2H_EQOS_RXQ_CTL2_PSRQ2_SHIFT;

		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL2);
		break;
	case T2H_EQOS_QUEUE_NUM_FOUR:
		/* Assign vlan tag 0\7 to queue 0. */
		value = T2H_EQOS_FOUR_QUEUE_Q_0;
		/* Assign vlan tag 1\6 to queue 1. */
		value |= T2H_EQOS_FOUR_QUEUE_Q_1 << T2H_EQOS_RXQ_CTL2_PSRQ1_SHIFT;
		/* Assign vlan tag 2\5 to queue 2. */
		value |= T2H_EQOS_FOUR_QUEUE_Q_2 << T2H_EQOS_RXQ_CTL2_PSRQ2_SHIFT;
		/* Assign vlan tag 3\4 to queue 3. */
		value |= T2H_EQOS_FOUR_QUEUE_Q_3 << T2H_EQOS_RXQ_CTL2_PSRQ3_SHIFT;

		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL2);
		break;
	case T2H_EQOS_QUEUE_NUM_FIVE:
		/* Assign vlan tag 0\5 to queue 0. */
		value = T2H_EQOS_FIVE_QUEUE_Q_0;
		/* Assign vlan tag 1\4 to queue 1. */
		value |= T2H_EQOS_FIVE_QUEUE_Q_1 << T2H_EQOS_RXQ_CTL2_PSRQ1_SHIFT;
		/* Assign vlan tag 2\3 to queue 2. */
		value |= T2H_EQOS_FIVE_QUEUE_Q_2 << T2H_EQOS_RXQ_CTL2_PSRQ2_SHIFT;
		/* Assign vlan tag 6 to queue 3. */
		value |= T2H_EQOS_QUEUE_MAP_6 << T2H_EQOS_RXQ_CTL2_PSRQ3_SHIFT;
		/* Assign vlan tag 7 to queue 4. */
		value2 = T2H_EQOS_QUEUE_MAP_7;

		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL2);
		rte_write32(rte_cpu_to_le_32(value2),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL3);
		break;
	case T2H_EQOS_QUEUE_NUM_SIX:
		/* Assign vlan tag 0\3 to queue 0. */
		value = T2H_EQOS_SIX_QUEUE_Q_0;
		/* Assign vlan tag 1\2 to queue 1. */
		value |= T2H_EQOS_SIX_QUEUE_Q_1 << T2H_EQOS_RXQ_CTL2_PSRQ1_SHIFT;
		/* Assign vlan tag 4 to queue 2. */
		value |= T2H_EQOS_QUEUE_MAP_4 << T2H_EQOS_RXQ_CTL2_PSRQ2_SHIFT;
		/* Assign vlan tag 5 to queue 3. */
		value |= T2H_EQOS_QUEUE_MAP_5 << T2H_EQOS_RXQ_CTL2_PSRQ3_SHIFT;
		/* Assign vlan tag 6 to queue 4. */
		value2 = T2H_EQOS_QUEUE_MAP_6;
		/* Assign vlan tag 7 to queue 5. */
		value2 |= T2H_EQOS_QUEUE_MAP_7 << T2H_EQOS_RXQ_CTL3_PSRQ5_SHIFT;

		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL2);
		rte_write32(rte_cpu_to_le_32(value2),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL3);
		break;
	case T2H_EQOS_QUEUE_NUM_SEVEN:
		/* Assign vlan tag 0 to queue 0. */
		value = T2H_EQOS_QUEUE_MAP_0;
		/* Assign vlan tag 1\2 to queue 1. */
		value |= T2H_EQOS_SEVEN_QUEUE_Q_1 << T2H_EQOS_RXQ_CTL2_PSRQ1_SHIFT;
		/* Assign vlan tag 3 to queue 2. */
		value |= T2H_EQOS_QUEUE_MAP_3 << T2H_EQOS_RXQ_CTL2_PSRQ2_SHIFT;
		/* Assign vlan tag 4 to queue 3. */
		value |= T2H_EQOS_QUEUE_MAP_4 << T2H_EQOS_RXQ_CTL2_PSRQ3_SHIFT;
		/* Assign vlan tag 5 to queue 4. */
		value2 = T2H_EQOS_QUEUE_MAP_5;
		/* Assign vlan tag 6 to queue 5. */
		value2 |= T2H_EQOS_QUEUE_MAP_6 << T2H_EQOS_RXQ_CTL3_PSRQ5_SHIFT;
		/* Assign vlan tag 7 to queue 6. */
		value2 |= T2H_EQOS_QUEUE_MAP_7 << T2H_EQOS_RXQ_CTL3_PSRQ6_SHIFT;

		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL2);
		rte_write32(rte_cpu_to_le_32(value2),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL3);
		break;
	case T2H_EQOS_QUEUE_NUM_EIGHT:
		/* Assign vlan tag 0 to queue 0. */
		value = T2H_EQOS_QUEUE_MAP_0;
		/* Assign vlan tag 1 to queue 1. */
		value |= T2H_EQOS_QUEUE_MAP_1 << T2H_EQOS_RXQ_CTL2_PSRQ1_SHIFT;
		/* Assign vlan tag 2 to queue 2. */
		value |= T2H_EQOS_QUEUE_MAP_2 << T2H_EQOS_RXQ_CTL2_PSRQ2_SHIFT;
		/* Assign vlan tag 3 to queue 3. */
		value |= T2H_EQOS_QUEUE_MAP_3 << T2H_EQOS_RXQ_CTL2_PSRQ3_SHIFT;
		/* Assign vlan tag 4 to queue 4. */
		value2 = T2H_EQOS_QUEUE_MAP_4;
		/* Assign vlan tag 5 to queue 5. */
		value2 |= T2H_EQOS_QUEUE_MAP_5 << T2H_EQOS_RXQ_CTL3_PSRQ5_SHIFT;
		/* Assign vlan tag 6 to queue 6. */
		value2 |= T2H_EQOS_QUEUE_MAP_6 << T2H_EQOS_RXQ_CTL3_PSRQ6_SHIFT;
		/* Assign vlan tag 7 to queue 7. */
		value2 |= T2H_EQOS_QUEUE_MAP_7 << T2H_EQOS_RXQ_CTL3_PSRQ7_SHIFT;

		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL2);
		rte_write32(rte_cpu_to_le_32(value2),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL3);
		break;
	default:
		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL2);
		break;
	}
}

static void
t2h_eqos_mtl_rxq_control(struct renesas_t2h_private *priv)
{
	for (uint32_t queue = 0; queue < priv->rx_queues_to_use; queue++) {
		uint32_t value =
			rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
						    T2H_EQOS_MTL_RXQ_CONTROL_BASE_ADDR(queue)));

		value &= ~T2H_EQOS_MTL_RXQ_CONTROL_WEGT_MASK;
		value |= T2H_EQOS_RXQ_DEF_WEGT & T2H_EQOS_MTL_RXQ_CONTROL_WEGT_MASK;
		value |= T2H_EQOS_MTL_RXQ_CONTROL_RXQ_FRM_ARBIT;
		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v +
				    T2H_EQOS_MTL_RXQ_CONTROL_BASE_ADDR(queue));
	}
}

static void
t2h_eqos_set_tx_queue_weight(struct renesas_t2h_private *priv)
{
	for (uint32_t queue = 0; queue < priv->tx_queues_to_use; queue++) {
		uint32_t value =
			rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
						    T2H_EQOS_MTL_TXQX_WEIGHT_BASE_ADDR(queue)));

		value &= ~T2H_EQOS_MTL_TXQ_WEIGHT_ISCQW_MASK;
		value |= T2H_EQOS_TXQ_DEF_WEGT & T2H_EQOS_MTL_TXQ_WEIGHT_ISCQW_MASK;
		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v +
				    T2H_EQOS_MTL_TXQX_WEIGHT_BASE_ADDR(queue));
	}
}

static void
t2h_eqos_mtl_configuration(struct renesas_t2h_private *priv)
{
	uint32_t rxq_cnt = priv->rx_queues_to_use;
	uint32_t txq_cnt = priv->tx_queues_to_use;
	uint32_t queue;

	for (queue = 0; queue < rxq_cnt; queue++) {
		/* Mapping RX queue to DMA Channel */
		t2h_eqos_rx_queue_dma_chan_map(priv, queue);
	}

	if (rxq_cnt > T2H_EQOS_DEF_QUEUE_NUM) {
		t2h_eqos_mtl_rxq_control(priv);
		/* Configure RXQ Algorithm to WSP */
		t2h_eqos_mtl_rx_algorithms(priv);
		/* Assign priority to each RXQ */
		t2h_eqos_rx_queue_priority(priv);
	}
	if (txq_cnt > T2H_EQOS_DEF_QUEUE_NUM) {
		t2h_eqos_mtl_tx_algorithms(priv);
		t2h_eqos_set_tx_queue_weight(priv);
	}
}

static void
t2h_eqos_mac_enable_rx_queues(struct renesas_t2h_private *priv)
{
	uint32_t rxq_cnt = priv->rx_queues_to_use;
	uint32_t queue;
	uint32_t value;

	for (queue = 0; queue < rxq_cnt; queue++) {
		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL0));
		value &= T2H_EQOS_RX_QUEUE_CLEAR(queue);
		value |= T2H_EQOS_RX_DCB_QUEUE_ENABLE(queue);
		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_RXQ_CTRL0);
	}
}

static void
t2h_eqos_rx_ipc_enable(struct renesas_t2h_private *priv)
{
	uint32_t value =
		rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG));
	value |= T2H_EQOS_MAC_CONFIG_IPC;
	rte_write32(rte_cpu_to_le_32(value), (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG);
}

static void
t2h_eqos_set_rings_length(struct renesas_t2h_private *priv, uint32_t rx_cnt, uint32_t tx_cnt)
{
	uint32_t queue;

	/* set Transmit Descriptor Ring Length */
	for (queue = 0; queue < tx_cnt; queue++) {
		rte_write32(rte_cpu_to_le_32(priv->dma_tx_size - T2H_EQOS_DEF_QUEUE_SUB),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_RING_LEN(queue));
	}
	/* set Receive Descriptor Ring Length */
	for (queue = 0; queue < rx_cnt; queue++) {
		rte_write32(rte_cpu_to_le_32(priv->dma_rx_size - T2H_EQOS_DEF_QUEUE_SUB),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_RING_LEN(queue));
	}
}

static void
t2h_eqos_config_hw_tstamping(struct renesas_t2h_private *priv)
{
	uint32_t value = T2H_EQOS_PTP_TCR_TSENA;

	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_TIMESTAMP_CTRL);
}

static void
t2h_eqos_start_all_dma(struct renesas_t2h_private *priv, uint32_t rx_dma_cnt, uint32_t tx_dma_count)
{
	uint32_t chan = 0;

	/* start RX DMA channels */
	for (chan = 0; chan < rx_dma_cnt; chan++) {
		uint32_t rx_value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_CTRL(chan)));
		rx_value |= T2H_EQOS_DMA_CH_RX_CTRL_SR;
		rte_write32(rte_cpu_to_le_32(rx_value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_CTRL(chan));
		rx_value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG));
		rx_value |= T2H_EQOS_MAC_CONFIG_RE;
		rte_write32(rte_cpu_to_le_32(rx_value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG);
	}

	/* start TX DMA channels */
	for (chan = 0; chan < tx_dma_count; chan++) {
		uint32_t tx_value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_CTRL(chan)));
		tx_value |= T2H_EQOS_DMA_CH_TX_CTRL_ST;
		rte_write32(rte_cpu_to_le_32(tx_value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_CTRL(chan));
		tx_value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG));
		tx_value |= T2H_EQOS_MAC_CONFIG_TE;
		rte_write32(rte_cpu_to_le_32(tx_value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG);
	}
}

static void
t2h_eqos_stop_all_dma(struct renesas_t2h_private *priv, uint32_t rx_dma_cnt, uint32_t tx_dma_cnt)
{
	uint32_t chan = 0;

	/* stop RX DMA channels */
	for (chan = 0; chan < rx_dma_cnt; chan++) {
		uint32_t rx_value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_CTRL(chan)));
		rx_value &= ~T2H_EQOS_DMA_CH_RX_CTRL_SR;
		rte_write32(rte_cpu_to_le_32(rx_value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_CTRL(chan));
	}

	/* stop RX DMA channels */
	for (chan = 0; chan < tx_dma_cnt; chan++) {
		uint32_t tx_value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_CTRL(chan)));
		tx_value &= ~T2H_EQOS_DMA_CH_TX_CTRL_ST;
		rte_write32(rte_cpu_to_le_32(tx_value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_CTRL(chan));
		tx_value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG));
		tx_value &= ~T2H_EQOS_MAC_CONFIG_TE;
		rte_write32(rte_cpu_to_le_32(tx_value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_CONFIG);
	}
}

static void
t2h_eqos_dma_axi(struct renesas_t2h_private *priv)
{
	uint32_t value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_SYS_BUS_MODE));

	value = (T2H_EQOS_AXI_WR_OSR_LMT << T2H_EQOS_DMA_AXI_WR_OSR_LMT_SHIFT) |
		(T2H_EQOS_AXI_RD_OSR_LMT << T2H_EQOS_DMA_AXI_RD_OSR_LMT_SHIFT) |
		T2H_EQOS_DMA_SYS_BUS_AAL | T2H_EQOS_DMA_AXI_BLEN16 | T2H_EQOS_DMA_AXI_BLEN8 |
		T2H_EQOS_DMA_AXI_BLEN4;

	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_SYS_BUS_MODE);
}

static int
t2h_qos_init_dma_engine(struct renesas_t2h_private *priv)
{
	uint32_t chan = 0;
	int ret	      = 0;
	struct t2h_eqos_priv_rx_q *rxq;
	struct t2h_eqos_priv_tx_q *txq;

	ret = t2h_eqos_dma_reset(priv);
	if (ret) {
		T2H_EQOS_PMD_ERR("Reset DMA Failed");
		return ret;
	}

	/* 1US TIC Counter */
	rte_write32(rte_cpu_to_le_32(T2H_EQOS_TIC_COUNTER),
		    (uint8_t *)priv->hw_baseaddr_v + T2J_EQOS_MAC_1US_TIC_COUNTER);

	/* Config DMA SysBus Mode */
	t2h_eqos_dma_init(priv);

	t2h_eqos_dma_axi(priv);

	/* Config All DMA RX Channel */
	for (chan = 0; chan < priv->rx_queues_to_use; chan++) {
		rxq = priv->dev->data->rx_queues[chan];
		t2h_eqos_init_rx_chan(priv, rxq);
	}

	/* Config All DMA TX Channel */
	for (chan = 0; chan < priv->tx_queues_to_use; chan++) {
		txq = priv->dev->data->tx_queues[chan];
		t2h_eqos_init_tx_chan(priv, txq);
	}

	return ret;
}

static void
configure_rx_flow_control(uint32_t rxq_size_val, uint32_t *rx_op_val)
{
	unsigned int rfd, rfa;

	if (rxq_size_val == T2H_EQOS_QUEUE_SIZE_4K) {
		rfd = T2H_EQOS_RFD_3;
		rfa = T2H_EQOS_RFA_1;
	} else {
		rfd = T2H_EQOS_RFD_7;
		rfa = T2H_EQOS_RFA_4;
	}

	*rx_op_val = (*rx_op_val & ~T2H_EQOS_MTL_OP_MODE_RFD_MASK) |
		     (rfd << T2H_EQOS_MTL_OP_MODE_RFD_SHIFT);
	*rx_op_val = (*rx_op_val & ~T2H_EQOS_MTL_OP_MODE_RFA_MASK) |
		     (rfa << T2H_EQOS_MTL_OP_MODE_RFA_SHIFT);
}

static void
t2h_eqos_dma_operation_mode(struct renesas_t2h_private *priv)
{
	uint32_t rx_dma_cnt = priv->rx_queues_to_use;
	uint32_t tx_dma_cnt = priv->tx_queues_to_use;
	uint32_t chan;
	uint32_t mtl_rx_val, mtl_tx_val, value;
	uint32_t rxq_size, txq_size;
	unsigned int rqs, tqs;

	rxq_size = priv->rx_fifo_size;
	rxq_size /= rx_dma_cnt;
	txq_size = priv->tx_fifo_size;
	txq_size /= tx_dma_cnt;
	rqs = rxq_size / T2H_EQOS_DEF_QUEUE_BYTE - T2H_EQOS_DEF_QUEUE_SUB;
	tqs = txq_size / T2H_EQOS_DEF_QUEUE_BYTE - T2H_EQOS_DEF_QUEUE_SUB;
	/* RX Operation Mode */
	for (chan = 0; chan < rx_dma_cnt; chan++) {

		mtl_rx_val = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
							 T2H_EQOS_MTL_CHAN_RX_OP_MODE(chan)));

		mtl_rx_val |= T2H_EQOS_MTL_OP_MODE_RSF;
		mtl_rx_val &= ~T2H_EQOS_MTL_OP_MODE_RQS_MASK;
		mtl_rx_val |= rqs << T2H_EQOS_MTL_OP_MODE_RQS_SHIFT;
		if (rxq_size >= T2H_EQOS_QUEUE_SIZE_4K) {
			configure_rx_flow_control(rxq_size, &mtl_rx_val);
		}
		rte_write32(rte_cpu_to_le_32(mtl_rx_val),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MTL_CHAN_RX_OP_MODE(chan));

		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_CTRL(chan)));
		value &= ~T2H_EQOS_DMA_RBSZ_MASK;
		value |= (priv->buf_size << T2H_EQOS_DMA_RBSZ_SHIFT) & T2H_EQOS_DMA_RBSZ_MASK;

		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_CTRL(chan));
	}

	/* TX Operation Mode */
	for (chan = 0; chan < tx_dma_cnt; chan++) {
		mtl_tx_val = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
							 T2H_EQOS_MTL_CHAN_TX_OP_MODE(chan)));

		mtl_tx_val |= T2H_EQOS_MTL_OP_MODE_TSF;
		mtl_tx_val &= ~T2H_EQOS_MTL_OP_MODE_TXQEN_MASK;
		mtl_tx_val |= T2H_EQOS_MTL_OP_MODE_TXQEN;

		mtl_tx_val &= ~T2H_EQOS_MTL_OP_MODE_TQS_MASK;
		mtl_tx_val |= tqs << T2H_EQOS_MTL_OP_MODE_TQS_SHIFT;

		rte_write32(rte_cpu_to_le_32(mtl_tx_val),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MTL_CHAN_TX_OP_MODE(chan));
	}
}

static void
t2h_eqos_mmc_setup(struct renesas_t2h_private *priv)
{
	uint32_t mode = T2H_EQOS_MMC_CNTRL_RESET_ON_READ | T2H_EQOS_MMC_CNTRL_COUNTER_RESET |
			T2H_EQOS_MMC_CNTRL_PRESET | T2H_EQOS_MMC_CNTRL_FULL_HALF_PRESET;

	/* Enable all MMC IRQ */
	rte_write32(rte_cpu_to_le_32(T2H_EQOS_MMC_RXTX_DEFAULT_MASK),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_INTR_MASK);
	rte_write32(rte_cpu_to_le_32(T2H_EQOS_MMC_RXTX_DEFAULT_MASK),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_INTR_MASK);
	rte_write32(rte_cpu_to_le_32(T2H_EQOS_MMC_DEFAULT_MASK),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPC_INTR_MASK);

	uint32_t value =
		rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_CNTRL));

	value |= (mode & T2H_EQOS_MMC_DEF_CTL);

	rte_write32(rte_cpu_to_le_32(value), (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_CNTRL);

	/* Reset stats */
	memset(&priv->mmc_stats, T2H_EQOS_EMPTY_MASK, sizeof(struct t2h_eqos_mmc_stats));

}

static void
t2h_eqos_enable_sph(struct renesas_t2h_private *priv, bool enable)
{
	uint32_t value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_EXT_CONFIG));

	value &= ~T2H_EQOS_MAC_CONFIG_HDSMS;
	value |= T2H_EQOS_MAC_CONFIG_HDSMS_256;
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_EXT_CONFIG);

	for (uint32_t chan = 0; chan < priv->rx_queues_to_use; chan++) {
		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_CTRL(chan)));

		if (enable)
			value |= T2H_EQOS_DMA_CH_CTRL_SPH;
		else
			value &= ~T2H_EQOS_DMA_CH_CTRL_SPH;
		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_CTRL(chan));
	}
}

static int
t2h_eqos_enable_tbs(struct renesas_t2h_private *priv, bool enable)
{
	for (uint32_t chan = 0; chan < priv->tx_queues_to_use; chan++) {
		uint32_t value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_CTRL(chan)));
		if (enable)
			value |= T2H_EQOS_DMA_CH_TX_CTRL_EDSE;
		else
			value &= ~T2H_EQOS_DMA_CH_TX_CTRL_EDSE;

		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_CTRL(chan));

		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_CTRL(chan)));

		if (enable && !(value & T2H_EQOS_DMA_CH_TX_CTRL_EDSE))
			return -1;
	}

	rte_write32(rte_cpu_to_le_32(T2H_EQOS_DMA_TBS_DEF_FTOS),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_TBS_CTRL);

	return 0;
}

static int
t2h_eqos_hw_setup(struct renesas_t2h_private *priv)
{
	uint32_t rx_dma_cnt = priv->rx_queues_to_use;
	uint32_t tx_dma_cnt = priv->tx_queues_to_use;
	uint32_t chan       = 0;
	int ret             = 0;
	int i;

	/* DMA Init*/
	ret = t2h_qos_init_dma_engine(priv);
	if (ret < 0) {
		T2H_EQOS_PMD_ERR("DMA Init Failed");
		return ret;
	}

	/* Init MAC Configuration */
	t2h_eqos_core_init(priv);

	/* In the case of multiple queues, configure MTL */
	t2h_eqos_mtl_configuration(priv);

	/* Set each RXQ to Enable */
	t2h_eqos_mac_enable_rx_queues(priv);

	t2h_eqos_rx_ipc_enable(priv);

	t2h_eqos_config_hw_tstamping(priv);

	/* Enable Receiver and Transmitter */
	t2h_eqos_set_mac(priv, true);

	/* RX/TX Operation Mode Config */
	t2h_eqos_dma_operation_mode(priv);

	t2h_eqos_mmc_setup(priv);

	/* Convert the timer from msec to usec */
	for (chan = 0; chan < rx_dma_cnt; chan++)
		rte_write32(rte_cpu_to_le_32(T2H_EQOS_DEF_DMA_RWT),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_WATCHDOG(chan));

	/* set Transmit/Receive Descriptor Ring Length */
	t2h_eqos_set_rings_length(priv, rx_dma_cnt, tx_dma_cnt);

	t2h_eqos_enable_sph(priv, false);

	t2h_eqos_enable_tbs(priv, false);

	/* Start RX and TX DMA Channels */
	t2h_eqos_start_all_dma(priv, rx_dma_cnt, tx_dma_cnt);

	for (i = 1; i <= T2H_EQOS_MAX_ADDR; i++) {
		rte_write32(0, (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_ADDR_HI(i));
		rte_write32(0, (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_ADDR_LO(i));
	}

	return 0;
}

static int
t2h_eqos_enable_interrupts(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv    = dev->data->dev_private;
	int ret;
	struct rte_intr_handle *intr_handle = dev->intr_handle;
	uint32_t dma_csr_ch                 = max(priv->rx_queues_to_use, priv->tx_queues_to_use);
	uint32_t value                      = 0;

	/* if the interrupts were configured on this devices */
	if (intr_handle && rte_intr_fd_get(intr_handle)) {
		if (dev->data->dev_conf.intr_conf.lsc != 0) {
			/* register a callback handler with UIO for interrupt notifications */
			ret = rte_intr_callback_register(intr_handle, t2h_eqos_dev_intr_handler,
							 (void *)dev);
			if (ret < 0) {
				T2H_EQOS_PMD_ERR(
					"Failed to register UIO interrupt callback, ret=%d", ret);
				return ret;
			}
		}

		/* enable UIO interrupt handling */
		ret = rte_intr_enable(intr_handle);
		if (ret < 0) {
			T2H_EQOS_PMD_ERR("Failed to enable UIO interrupts, ret=%d", ret);
			if (dev->data->dev_conf.intr_conf.lsc != 0) {
				rte_intr_callback_unregister(intr_handle, t2h_eqos_dev_intr_handler,
							     (void *)dev);
			}
			dev->data->dev_conf.intr_conf.lsc = 0;
			dev->data->dev_flags &= ~RTE_ETH_DEV_INTR_LSC;
			return ret;
		}
	}

	value = T2H_EQOS_MAC_INT_DEF_ENABLE;

	rte_write32(rte_cpu_to_le_32(value), (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_INT_EN);

	/* Disable all DMA IRQ */
	for (uint32_t chan = 0; chan < dma_csr_ch; chan++) {
		rte_write32(0, (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_INTR_ENA(chan));
	}

	return ret;
}

static int
t2h_eqos_disable_interrupts(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv    = dev->data->dev_private;
	int ret;
	struct rte_intr_handle *intr_handle = dev->intr_handle;
	uint32_t dma_csr_ch                 = max(priv->rx_queues_to_use, priv->tx_queues_to_use);

	/* inform the device that all interrupts are disabled */
	for (uint32_t chan = 0; chan < dma_csr_ch; chan++) {
		rte_write32(rte_cpu_to_le_32(T2H_EQOS_DMA_CH_INTR_ENA_NO_INTRS),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_INTR_ENA(chan));
	}

	if (intr_handle && rte_intr_fd_get(intr_handle)) {
		/* disable uio intr before callback unregister */
		ret = rte_intr_disable(intr_handle);
		if (ret < 0) {
			T2H_EQOS_PMD_WARN("Failed to disable UIO interrupts, ret=%d", ret);
		}

		if (dev->data->dev_conf.intr_conf.lsc != 0) {
			ret = rte_intr_callback_unregister(intr_handle, t2h_eqos_dev_intr_handler,
							   (void *)dev);
			if (ret < 0) {
				T2H_EQOS_PMD_WARN(
					"Failed to unregister UIO interrupt callback, ret=%d", ret);
			}
		}
	}

	return 0;
}

static int
t2h_eqos_restart(struct rte_eth_dev *dev)
{
	int ret;
	int bfsize                       = 0;
	struct renesas_t2h_private *priv = dev->data->dev_private;

	priv->rx_queues_to_use = dev->data->nb_rx_queues;
	priv->tx_queues_to_use = dev->data->nb_tx_queues;
	if (unlikely(dev->data->mtu >= T2H_EQOS_BUF_SIZE_8KB))
		bfsize = T2H_EQOS_BUF_SIZE_16KB;
	if (bfsize < T2H_EQOS_BUF_SIZE_16KB) {
		if (dev->data->mtu >= T2H_EQOS_BUF_SIZE_8KB)
			bfsize = T2H_EQOS_BUF_SIZE_16KB;
		else if (dev->data->mtu >= T2H_EQOS_BUF_SIZE_4KB)
			bfsize = T2H_EQOS_BUF_SIZE_8KB;
		else if (dev->data->mtu >= T2H_EQOS_BUF_SIZE_2KB)
			bfsize = T2H_EQOS_BUF_SIZE_4KB;
		else if (dev->data->mtu > T2H_EQOS_DEF_BUF_SIZE)
			bfsize = T2H_EQOS_BUF_SIZE_2KB;
		else
			bfsize = T2H_EQOS_DEF_BUF_SIZE;
	}
	priv->buf_size = bfsize;

	ret = t2h_eqos_hw_setup(priv);
	if (ret < 0) {
		T2H_EQOS_PMD_ERR("HW Set Up Failed");
		return ret;
	}

	t2h_eqos_enable_interrupts(dev);

	return 0;
}

static int
t2h_eqos_eth_start(struct rte_eth_dev *dev)
{
	uint16_t i;
	uint16_t rx_num = dev->data->nb_rx_queues;
	uint16_t tx_num = dev->data->nb_tx_queues;
	int ret         = 0;

	ret = t2h_eqos_restart(dev);
	if (ret < 0) {
		return ret;
	}

	dev->rx_pkt_burst = &t2h_eqos_recv_pkts;
	dev->tx_pkt_burst = &t2h_eqos_xmit_pkts;

	for (i = 0; i < rx_num; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	for (i = 0; i < tx_num; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}

static void
t2h_eqos_disable(struct renesas_t2h_private *priv, uint16_t rx_num, uint16_t tx_num)
{
	/* Stop RX and TX DMA Channels */
	t2h_eqos_stop_all_dma(priv, rx_num, tx_num);

	t2h_eqos_set_mac(priv, false);
}

static int
t2h_eqos_eth_stop(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	uint16_t i;
	uint16_t rx_num = dev->data->nb_rx_queues;
	uint16_t tx_num = dev->data->nb_tx_queues;

	dev->data->dev_started = 0;

	t2h_eqos_disable(priv, rx_num, tx_num);
	t2h_eqos_disable_interrupts(dev);

	for (i = 0; i < rx_num; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	for (i = 0; i < tx_num; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;

	return 0;
}

static int
t2h_eqos_eth_close(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;

	t2h_eqos_free_all_queues(dev);

	t2h_eqos_uio_cleanup(priv);

	rte_intr_dev_fd_set(dev->intr_handle, -1);
	rte_intr_instance_free(dev->intr_handle);
	dev->intr_handle = NULL;

	return 0;
}

static void
t2h_eqos_write_single_vlan(struct renesas_t2h_private *priv, uint16_t vid)
{
	uint32_t val;

	val = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG));
	val &= ~T2H_EQOS_MAC_VLAN_TAG_VID;
	val |= T2H_EQOS_MAC_VLAN_TAG_ETV | vid;

	rte_write32(rte_cpu_to_le_32(val), (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG);
}

static int
t2h_eqos_write_vlan_filter(struct renesas_t2h_private *priv, uint8_t idx, uint32_t data)
{
	int i, try_counter = T2H_EQOS_VLAN_TIMEOUT_CNT;
	uint32_t val;

	if (idx >= priv->vlan_num)
		return -EINVAL;

	rte_write32(rte_cpu_to_le_32(data),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG_DATA);

	val = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG));
	val &= ~(T2H_EQOS_MAC_VLAN_TAG_OFS_MASK | T2H_EQOS_MAC_VLAN_TAG_CT |
		 T2H_EQOS_MAC_VLAN_TAG_OB);
	val |= (idx << T2H_EQOS_MAC_VLAN_TAG_OFS_SHIFT) | T2H_EQOS_MAC_VLAN_TAG_OB;
	rte_write32(rte_cpu_to_le_32(val), (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG);

	while (try_counter) {
		val = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG));
		if (!(val & T2H_EQOS_MAC_VLAN_TAG_OB))
			return 0;
		try_counter--;
		T2H_EQOS_UDELAY(T2H_EQOS_VLAN_DELAY_TIME);
	}
	T2H_EQOS_PMD_WARN("Register MAC_VLAN_Tag_Silter processing timeout");
	return -EBUSY;
}

static int
t2h_eqos_vlan_promisc_enable(struct renesas_t2h_private *priv)
{
	uint32_t value;
	uint32_t hash_val;
	int i;
	int ret;

	/* Only one VLAN */
	if (priv->vlan_num == 1) {
		t2h_eqos_write_single_vlan(priv, 0);
		return 0;
	}

	for (i = 0; i < priv->vlan_num; i++) {
		if (priv->filter_set[i] & T2H_EQOS_MAC_VLAN_TAG_DATA_VEN) {
			value = priv->filter_set[i] & ~T2H_EQOS_MAC_VLAN_TAG_DATA_VEN;
			ret = t2h_eqos_write_vlan_filter(priv, i, value);
			if (ret) {
				T2H_EQOS_PMD_ERR("Failed Write Vlan Filter");
				return ret;
			}
		}
	}

	hash_val = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_HASH_TABLE));
	if (hash_val & T2H_EQOS_MAC_VLAN_VLHT) {
		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG));
		if (value & T2H_EQOS_MAC_VLAN_TAG_VTHM) {
			value &= ~T2H_EQOS_MAC_VLAN_TAG_VTHM;
			rte_write32(rte_cpu_to_le_32(value),
				    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG);
		}
	}

	return 0;
}

static int
t2h_eqos_restore_hw_vlan_rx_fltr(struct renesas_t2h_private *priv)
{
	uint32_t value;
	uint32_t hash_val;
	int i;
	int ret;

	/* Only one VLAN */
	if (priv->vlan_num == 1) {
		t2h_eqos_write_single_vlan(priv, priv->filter_set[0]);
		return 0;
	}

	for (i = 0; i < priv->vlan_num; i++) {
		if (priv->filter_set[i] & T2H_EQOS_MAC_VLAN_TAG_DATA_VEN) {
			value = priv->filter_set[i];
			ret = t2h_eqos_write_vlan_filter(priv, i, value);
			if (ret) {
				T2H_EQOS_PMD_ERR("Failed Write Vlan Filter");
				return ret;
			}
		}
	}

	hash_val = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_HASH_TABLE));
	if (hash_val & T2H_EQOS_MAC_VLAN_VLHT) {
		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG));
		value |= T2H_EQOS_MAC_VLAN_TAG_VTHM;
		rte_write32(rte_cpu_to_le_32(value),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG);
	}

	return 0;
}

static int
t2h_eqos_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	uint32_t value;
	int ret;

	value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER));
	value |= T2H_EQOS_MAC_PACKET_FILTER_PR;
	T2H_EQOS_PMD_DEBUG("The current MAC_Packet_Filter is 0x%x", value);
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER);
	if (!priv->promisc) {
		priv->promisc = T2H_EQOS_PROMISC_ON;
		ret = t2h_eqos_vlan_promisc_enable(priv);
		if (ret < 0) {
			T2H_EQOS_PMD_ERR("Promiscuous Enable Write Failed");
			return ret;
		}
	}

	return 0;
}

static int
t2h_eqos_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	uint32_t value;
	int ret;

	value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER));
	value &= ~T2H_EQOS_MAC_PACKET_FILTER_PR;
	T2H_EQOS_PMD_DEBUG("The current MAC_Packet_Filter is 0x%x", value);
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER);
	if (priv->promisc) {
		priv->promisc = T2H_EQOS_PROMISC_OFF;
		ret = t2h_eqos_restore_hw_vlan_rx_fltr(priv);
		if (ret < 0) {
			T2H_EQOS_PMD_ERR("Promiscuous Disable Write Failed");
			return ret;
		}
	}

	return 0;
}

static int
t2h_eqos_multicast_enable(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	uint32_t value;
	uint32_t filters[8];
	int hash_regs_cnt = BIT(priv->hash_tb_sz);

	value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER));

	/* Pass All Multicast is enabled */
	value |= T2H_EQOS_MAC_PACKET_FILTER_PM;
	T2H_EQOS_PMD_DEBUG("The current MAC_Packet_Filter is 0x%x", value);
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER);
	dev->data->all_multicast = T2H_EQOS_MULTICAST_ON;

	/* Enable All HASH Table */
	memset(filters, T2H_EQOS_FULL_MASK, sizeof(filters));
	for (int i = 0; i < hash_regs_cnt; i++)
		rte_write32(rte_cpu_to_le_32(filters[i]),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_HASH_TAB(i));

	return 0;
}

static int
t2h_eqos_allmulticast_disable(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	uint32_t value;
	uint32_t filters[8];
	int hash_regs_cnt = BIT(priv->hash_tb_sz);

	value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER));

	/* Pass All Multicast is Disable */
	value &= ~T2H_EQOS_MAC_PACKET_FILTER_PM;
	T2H_EQOS_PMD_DEBUG("The current MAC_Packet_Filter is 0x%x", value);
	/* Disable All Hash Table */
	memset(filters, T2H_EQOS_EMPTY_MASK, sizeof(filters));
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER);
	dev->data->all_multicast = T2H_EQOS_MULTICAST_OFF;

	for (int i = 0; i < hash_regs_cnt; i++)
		rte_write32(rte_cpu_to_le_32(filters[i]),
			    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_HASH_TAB(i));

	return 0;
}

static int
t2h_eqos_update_vlan_hash(struct renesas_t2h_private *priv, uint32_t hash, uint16_t p_match_val)
{
	uint32_t value;

	rte_write32(rte_cpu_to_le_32(hash),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_HASH_TABLE);

	value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG));

	if (hash) {
		value |= T2H_EQOS_MAC_VLAN_TAG_VTHM | T2H_EQOS_MAC_VLAN_TAG_ETV;
	} else {
		if (p_match_val) {
			value = T2H_EQOS_MAC_VLAN_TAG_ETV;
		} else {
			value &= ~(T2H_EQOS_MAC_VLAN_TAG_VTHM | T2H_EQOS_MAC_VLAN_TAG_ETV);
			value &= ~(T2H_EQOS_MAC_VLAN_TAG_EDVLP | T2H_EQOS_MAC_VLAN_TAG_ESVL);
			value &= ~T2H_EQOS_MAC_VLAN_TAG_DOVLTC;
			value &= ~T2H_EQOS_MAC_VLAN_TAG_VID;
		}
	}
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG);

	return 0;
}

static int
t2h_eqos_vlan_update(struct renesas_t2h_private *priv)
{
	uint32_t crc, hash = 0;
	uint16_t per_match = 0;
	uint16_t vid, v_mid;
	int cnt = 0;
	unsigned long vid_idx, vid_valid;

	/* Generate the VLAN Hash Table value */
	for (vid = 0; vid < T2H_EQOS_VLAN_N_VID; vid++) {
		vid_idx	  = T2H_EQOS_VLAN_TABLE_IDX(vid);
		vid_valid = priv->config_vlans[vid_idx];
		v_mid	  = (vid - (T2H_EQOS_VLANID_HASHTAV_MAX * vid_idx));
		vid_valid = (unsigned long)vid_valid >> v_mid;
		if (vid_valid & T2H_EQOS_VLANID_VALID) {
			T2H_EQOS_PMD_INFO("vid:%d vid_valid :%lu pdata->config_vlans[%ld]=0x%lx",
					  vid, vid_valid, vid_idx, priv->config_vlans[vid_idx]);
		} else {
			continue;
		}

		uint16_t vid_le = rte_cpu_to_le_16(vid);
		crc = t2h_eqos_bitrev32(~t2h_eqos_vid_crc32_le(vid_le)) >> T2H_EQOS_VLANID_CRC_MASK;
		hash |= (T2H_EQOS_VLANID_MASK << crc);
		cnt++;
		T2H_EQOS_PMD_DEBUG("vid:%d vid_idx:%ld vid_le:%d crc:%d hash:%d", vid, vid_idx,
				   vid_le, crc, hash);
	}

	if (!priv->vlhash) {
		if (cnt > T2H_EQOS_VLANID_DIS_COUNT)
			return -EOPNOTSUPP;
		per_match = rte_cpu_to_le_16(vid);
		hash	  = 0;
	}

	return t2h_eqos_update_vlan_hash(priv, hash, per_match);
}

static int
t2h_eqos_add_hw_vlan_rx_fltr(struct renesas_t2h_private *priv, uint16_t vlan_id)
{
	int index    = -1, ret;
	uint32_t val = 0;
	uint32_t i;

	if (vlan_id > T2H_EQOS_VLANID_MAX) {
		return -EINVAL;
	}

	/* Only one VLAN */
	if (priv->vlan_num == 1) {
		/* Promiscuous Mode not set */
		if (vlan_id == T2H_EQOS_VLANID_ZERO) {
			T2H_EQOS_PMD_WARN("Adding VLAN ID 0 is not supported");
			return -EPERM;
		}

		if (priv->filter_set[0] & T2H_EQOS_MAC_VLAN_TAG_VID) {
			T2H_EQOS_PMD_ERR("Only single VLAN ID supported");
			return -EPERM;
		}

		priv->filter_set[0] = vlan_id;
		t2h_eqos_write_single_vlan(priv, vlan_id);
		return 0;
	}

	val |= T2H_EQOS_MAC_VLAN_TAG_DATA_ETV | T2H_EQOS_MAC_VLAN_TAG_DATA_VEN | vlan_id;
	T2H_EQOS_PMD_DEBUG("vlan_num == %d val = 0x%x", priv->vlan_num, val);
	for (i = 0; i < priv->vlan_num; i++) {
		if (priv->filter_set[i] == val)
			return 0;
		else if (!(priv->filter_set[i] & T2H_EQOS_MAC_VLAN_TAG_DATA_VEN))
			index = i;
	}

	if (index == -1) {
		T2H_EQOS_PMD_ERR("MAC_VLAN_Tag_Filter is full size = %u", priv->vlan_num);
		return -EPERM;
	}
	T2H_EQOS_PMD_DEBUG("index = %d", index);
	ret = t2h_eqos_write_vlan_filter(priv, index, val);

	if (!ret)
		priv->filter_set[index] = val;

	return ret;
}

static int
t2h_eqos_vlan_rx_add_vid(struct renesas_t2h_private *priv, uint16_t vlan_id)
{
	int ret;
	unsigned long vid_bit, vid_idx;

	vid_bit = T2H_EQOS_VLAN_TABLE_BIT(vlan_id);
	vid_idx = T2H_EQOS_VLAN_TABLE_IDX(vlan_id);

	priv->config_vlans[vid_idx] |= vid_bit;

	ret = t2h_eqos_vlan_update(priv);
	if (ret) {
		priv->config_vlans[vid_idx] &= ~vid_bit;
		T2H_EQOS_PMD_ERR("t2h_eqos_vlan_update error: %d", ret);
		return ret;
	}

	if (priv->vlan_num) {
		ret = t2h_eqos_add_hw_vlan_rx_fltr(priv, vlan_id);
		if (ret)
			return ret;
	}

	return 0;
}

static int
t2h_eqos_del_hw_vlan_rx_fltr(struct renesas_t2h_private *priv, uint16_t vid)
{
	int ret	   = 0;
	uint32_t i = 0;

	/* Only one Vlan */
	if (priv->vlan_num == 1) {
		if ((priv->filter_set[0] & T2H_EQOS_MAC_VLAN_TAG_VID) == vid) {
			priv->filter_set[0] = 0;
			t2h_eqos_write_single_vlan(priv, 0);
		}
		return 0;
	}

	for (i = 0; i < priv->vlan_num; i++) {
		if ((priv->filter_set[i] & T2H_EQOS_MAC_VLAN_TAG_DATA_VID) == vid) {
			ret = t2h_eqos_write_vlan_filter(priv, i, 0);

			if (!ret)
				priv->filter_set[i] = 0;
			else
				return ret;
		}
	}

	return ret;
}

static int
t2h_eqos_vlan_rx_kill_vid(struct renesas_t2h_private *priv, uint16_t vlan_id)
{
	int ret;
	unsigned long vid_bit, vid_idx;

	vid_bit = T2H_EQOS_VLAN_TABLE_BIT(vlan_id);
	vid_idx = T2H_EQOS_VLAN_TABLE_IDX(vlan_id);
	priv->config_vlans[vid_idx] &= ~vid_bit;

	if (priv->vlan_num) {
		ret = t2h_eqos_del_hw_vlan_rx_fltr(priv, vlan_id);
		if (ret)
			return ret;
	}
	ret = t2h_eqos_vlan_update(priv);

	return ret;
}

static int
t2h_eqos_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	int err;

	if (on) {
		err = t2h_eqos_vlan_rx_add_vid(priv, vlan_id);
	} else {
		err = t2h_eqos_vlan_rx_kill_vid(priv, vlan_id);
	}

	return err;
}

static void
t2h_eqos_vlan_filter_enable(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	uint32_t value, filter_value;

	filter_value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER));
	filter_value |= T2H_EQOS_MAC_PACKET_FILTER_VTFE;
	rte_write32(rte_cpu_to_le_32(filter_value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER);

	value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG));
	value |= T2H_EQOS_MAC_VLAN_TAG_VTHM | T2H_EQOS_MAC_VLAN_TAG_ETV;
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG);

}

static void
t2h_eqos_vlan_filter_disable(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	uint32_t value, filter_value;

	filter_value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER));
	filter_value &= ~T2H_EQOS_MAC_PACKET_FILTER_VTFE;
	rte_write32(rte_cpu_to_le_32(filter_value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_PACKET_FILTER);

	value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG));
	value &= ~(T2H_EQOS_MAC_VLAN_TAG_VTHM | T2H_EQOS_MAC_VLAN_TAG_ETV);
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VLAN_TAG);
}

static int
t2h_eqos_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	struct rte_eth_rxmode *rxmode;

	rxmode = &dev->data->dev_conf.rxmode;
	if (mask & RTE_ETH_VLAN_FILTER_MASK) {
		if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER) {
			t2h_eqos_vlan_filter_enable(dev);
		} else {
			t2h_eqos_vlan_filter_disable(dev);
		}
	}

	return 0;
}

static int
t2h_eqos_mtu_set(struct rte_eth_dev *dev, uint16_t new_mtu)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	int txq_sz			 = priv->tx_fifo_size;

	T2H_EQOS_PMD_DEBUG("now mtu = %d", dev->data->mtu);
	/* Is there a change in mtu setting */
	if (dev->data->mtu == new_mtu) {
		T2H_EQOS_PMD_INFO("There is no change in mtu setting");
		return 0;
	}

	/* mtu setting is forbidden if port is start */
	if (dev->data->dev_started != 0) {
		T2H_EQOS_PMD_ERR("port %d must be stopped before configuration",
				 dev->data->port_id);
		return -EBUSY;
	}

	txq_sz /= priv->tx_queues_to_use;

	if ((txq_sz < new_mtu) || (new_mtu > T2H_EQOS_BUF_SIZE_16KB))
		return -EINVAL;

	dev->data->mtu = new_mtu;
	T2H_EQOS_PMD_DEBUG("new mtu = %d", dev->data->mtu);
	return 0;
}

static inline int
t2h_eqos_read_regs(struct renesas_t2h_private *priv, uint32_t *reg_buf)
{
	uint32_t reg_addr[T2H_EQOS_REG_NUM];
	int i, v_count;
	uint32_t value;

	v_count = 0;

	for (i = 0; i < T2H_EQOS_MAC_REG_NUM; i++) {
		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + i * T2H_EQOS_REG_WIDTH));
		reg_addr[v_count]  = i * T2H_EQOS_REG_WIDTH;
		reg_buf[v_count++] = value;
	}

	for (i = 0; i < T2H_EQOS_DMA_REG_NUM; i++) {
		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_BUS_MODE +
								 i * T2H_EQOS_REG_WIDTH));
		reg_addr[v_count]  = T2H_EQOS_DMA_BUS_MODE + i * T2H_EQOS_REG_WIDTH;
		reg_buf[v_count++] = value;
	}

	for (i = 0; i < T2H_EQOS_DMA_CH_NB_MAX; i++) {
		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_CTRL(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_CTRL(i);
		reg_buf[v_count++] = value;

		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_CTRL(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_TX_CTRL(i);
		reg_buf[v_count++] = value;

		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_CTRL(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_RX_CTRL(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_TX_BASE_ADDR(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_TX_BASE_ADDR(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_RX_BASE_ADDR(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_RX_BASE_ADDR(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_TX_END_ADDR(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_TX_END_ADDR(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_RX_END_ADDR(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_RX_END_ADDR(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_TX_RING_LEN(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_TX_RING_LEN(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_RX_RING_LEN(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_RX_RING_LEN(i);
		reg_buf[v_count++] = value;

		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_INTR_ENA(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_INTR_ENA(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_RX_WATCHDOG(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_RX_WATCHDOG(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_SLOT_CTRL_STATUS(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_SLOT_CTRL_STATUS(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_CUR_TX_DESC(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_CUR_TX_DESC(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_CUR_RX_DESC(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_CUR_RX_DESC(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_CUR_TX_BUF_ADDR(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_CUR_TX_BUF_ADDR(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_CUR_RX_BUF_ADDR(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_CUR_RX_BUF_ADDR(i);
		reg_buf[v_count++] = value;

		value = rte_le_to_cpu_32(
			rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_STATUS(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_STATUS(i);
		reg_buf[v_count++] = value;

		value		   = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
								 T2H_EQOS_DMA_CH_MISS_FRAME_CNT(i)));
		reg_addr[v_count]  = T2H_EQOS_DMA_CH_MISS_FRAME_CNT(i);
		reg_buf[v_count++] = value;
	}

	for (i = 0; i < v_count; i++)
		T2H_EQOS_PMD_INFO("port id = %d address = 0x%x  value = 0x%x", 
				              priv->dev->data->port_id, reg_addr[i], reg_buf[i]);

	return v_count;
}

static void
t2h_get_desc(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	struct t2h_bufdesc *p;
	uint32_t des0, des1, des2, des3, q_idx;

	for (q_idx = 0; q_idx < priv->rx_queues_to_use; q_idx++) {
		struct t2h_eqos_priv_rx_q *rxq = dev->data->rx_queues[q_idx];
		for (uint32_t i = 0; i < priv->dma_rx_size; i++) {
			p    = (struct t2h_bufdesc *)(rxq->dma_rx + i);
			des0 = rte_le_to_cpu_32(rte_read32(&p->des0));
			des1 = rte_le_to_cpu_32(rte_read32(&p->des1));
			des2 = rte_le_to_cpu_32(rte_read32(&p->des2));
			des3 = rte_le_to_cpu_32(rte_read32(&p->des3));
			T2H_EQOS_PMD_DEBUG("port id %d rxq %d desc %03d : p = %p des0 = 0x%x, des1 "
					        "= 0x%x, des2 = 0x%x, des3 = 0x%x",
					        dev->data->port_id, q_idx, i, p, des0, des1, des2, des3);
		}
	}

	for (q_idx = 0; q_idx < priv->tx_queues_to_use; q_idx++) {
		struct t2h_eqos_priv_tx_q *txq = dev->data->tx_queues[q_idx];
		for (uint32_t i = 0; i < txq->nb_tx_desc; i++) {
			p    = (struct t2h_bufdesc *)(txq->tx_base + i);
			des0 = rte_le_to_cpu_32(rte_read32(&p->des0));
			des1 = rte_le_to_cpu_32(rte_read32(&p->des1));
			des2 = rte_le_to_cpu_32(rte_read32(&p->des2));
			des3 = rte_le_to_cpu_32(rte_read32(&p->des3));
			T2H_EQOS_PMD_DEBUG("port id %d txq %d desc %03d : p = %p des0 = 0x%x, des1 "
					        "= 0x%x, des2 = 0x%x, des3 = 0x%x",
					        dev->data->port_id, q_idx, i, p, des0, des1, des2, des3);
		}
	}
}

static int
t2h_eqos_get_regs(struct rte_eth_dev *dev, struct rte_dev_reg_info *regs)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	uint32_t *data                   = regs->data;

	if (data == NULL) {
		regs->length  = T2H_EQOS_REG_NUM;
		regs->width   = sizeof(uint32_t);
		regs->version = priv->version_id;
		return 0;
	}

	if (regs->length == 0) {
		t2h_eqos_read_regs(priv, &data[0]);
#if T2H_DEBUG
		t2h_get_desc(dev);
#endif
		return 0;
	}

	return 0;
}

static int
t2h_eqos_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	struct rte_eth_stats *eth_stats	 = &priv->stats;

	stats->ipackets  = eth_stats->ipackets;
	stats->ibytes    = eth_stats->ibytes;
	stats->ierrors   = eth_stats->ierrors;
	stats->opackets  = eth_stats->opackets;
	stats->obytes    = eth_stats->obytes;
	stats->oerrors   = eth_stats->oerrors;
	stats->rx_nombuf = eth_stats->rx_nombuf;

	return 0;
}

static const uint32_t *
t2h_eqos_supported_ptypes_get(struct rte_eth_dev *dev __rte_unused)
{
	static const uint32_t ptypes[] = {/* 'ether type'=[0x0800|0x86DD] */
					  RTE_PTYPE_L2_ETHER,
					  /* 'ether type'=0x0800 'version'=4, 'ihl'=5 */
					  RTE_PTYPE_L3_IPV4,
					  /* 'ether type'=0x86DD 'version'=6, 'next header'=17 */
					  RTE_PTYPE_L4_UDP,
					  /* 'ether type'=0x88F7> */
					  RTE_PTYPE_L2_ETHER_TIMESYNC,
					  /* <'ether type'=0x86DD 'version'=6, 'next header'=17> */
					  RTE_PTYPE_INNER_L4_UDP};

	return ptypes;
}

static int
t2h_eqos_stats_reset(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;

	/* Reset software totals */
	memset(&priv->stats, 0, sizeof(priv->stats));

	return 0;
}

static void
t2h_eqos_read_mmc_stats(struct renesas_t2h_private *priv)
{
	struct t2h_eqos_mmc_stats *stats = &priv->mmc_stats;

	stats->txoctetcount_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_OCTETCOUNT_GB));
	stats->txpacketscount_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_FRAMECOUNT_GB));
	stats->txbroadcastpackets_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_BROADCASTFRAME_G));
	stats->txmulticastpackets_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_MULTICASTFRAME_G));
	stats->tx64octets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_64_OCTETS_GB));
	stats->tx65to127octets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_65_TO_127_OCTETS_GB));
	stats->tx128to255octets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_128_TO_255_OCTETS_GB));
	stats->tx256to511octets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_256_TO_511_OCTETS_GB));
	stats->tx512to1023octets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_512_TO_1023_OCTETS_GB));
	stats->tx1024tomaxoctets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_1024_TO_MAX_OCTETS_GB));
	stats->txunicastpackets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_UNICAST_GB));
	stats->txmulticastpackets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_MULTICAST_GB));
	stats->txbroadcastpackets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_BROADCAST_GB));
	stats->txunderflowerror += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_UNDERFLOW_ERROR));
	stats->txsinglecollision_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_SINGLECOL_G));
	stats->txmultiplecollision_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_MULTICOL_G));
	stats->txdeferred += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_DEFERRED));
	stats->txlatecollision += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_LATECOL));
	stats->txexcessivecollision += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_EXESSCOL));
	stats->txcarriererror += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_CARRIER_ERROR));
	stats->txoctetcount_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_OCTETCOUNT_G));
	stats->txpacketcount_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_FRAMECOUNT_G));
	stats->txexcessivedeferral += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_EXCESSDEF));
	stats->txpausepackets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_PAUSE_FRAME));
	stats->txvlanpackets_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_VLAN_FRAME_G));

	stats->rxpacketcount_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_FRAMECOUNT_GB));
	stats->rxoctetcount_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_OCTETCOUNT_GB));
	stats->rxoctetcount_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_OCTETCOUNT_G));
	stats->rxbroadcastpackets_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_BROADCASTFRAME_G));
	stats->rxmulticastpackets_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_MULTICASTFRAME_G));
	stats->rxcrcerror += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_CRC_ERROR));
	stats->rxalignmenterror += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_ALIGN_ERROR));
	stats->rxrunterror += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_RUN_ERROR));
	stats->rxjabbererror += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_JABBER_ERROR));
	stats->rxundersize_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_UNDERSIZE_G));
	stats->rxoversize_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_OVERSIZE_G));
	stats->rx64octets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_64_OCTETS_GB));
	stats->rx65to127octets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_65_TO_127_OCTETS_GB));
	stats->rx128to255octets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_128_TO_255_OCTETS_GB));
	stats->rx256to511octets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_256_TO_511_OCTETS_GB));
	stats->rx512to1023octets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_512_TO_1023_OCTETS_GB));
	stats->rx1024tomaxoctets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_1024_TO_MAX_OCTETS_GB));
	stats->rxunicastpackets_g += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_UNICAST_G));
	stats->rxlengtherror += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_LENGTH_ERROR));
	stats->rxoutofrangetype += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_AUTOFRANGETYPE));
	stats->rxpausepackets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_PAUSE_FRAMES));
	stats->rxfifooverflow += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_FIFO_OVERFLOW));
	stats->rxvlanpackets_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_VLAN_FRAMES_GB));
	stats->rxwatchdogerror += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_WATCHDOG_ERROR));

	stats->rxipcintr += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPC_INTR));

	stats->rxipv4_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV4_GD));
	stats->rxipv4_hderr += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV4_HDERR));
	stats->rxipv4_nopay += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV4_NOPAY));
	stats->rxipv4_frag += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV4_FRAG));
	stats->rxipv4_udsbl += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV4_UDSBL));
	stats->rxipv4_gb_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV4_GD_OCTETS));
	stats->rxipv4_hderr_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV4_HDERR_OCTETS));
	stats->rxipv4_nopay_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV4_NOPAY_OCTETS));
	stats->rxipv4_frag_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV4_FRAG_OCTETS));
	stats->rxipv4_udsbl_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV4_UDSBL_OCTETS));

	stats->rxipv6_gb_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV6_GD_OCTETS));
	stats->rxipv6_hderr_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV6_HDERR_OCTETS));
	stats->rxipv6_nopay_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV6_NOPAY_OCTETS));
	stats->rxipv6_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV6_GD));
	stats->rxipv6_hderr += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV6_HDERR));
	stats->rxipv6_nopay += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_IPV6_NOPAY));

	stats->rxudp_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_UDP_GD));
	stats->rxudp_err += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_UDP_ERR));
	stats->rxtcp_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_TCP_GD));
	stats->rxtcp_err += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_TCP_ERR));
	stats->rxicmp_gb += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_ICMP_GD));
	stats->rxicmp_err += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_ICMP_ERR));
	stats->rxudp_gb_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_UDP_GD_OCTETS));
	stats->rxudp_err_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_UDP_ERR_OCTETS));
	stats->rxtcp_gb_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_TCP_GD_OCTETS));
	stats->rxtcp_err_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_TCP_ERR_OCTETS));
	stats->rxicmp_gb_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_ICMP_GD_OCTETS));
	stats->rxicmp_err_octets += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_ICMP_ERR_OCTETS));
	stats->txfpefragmentcntr += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_FPE_FRAG));
	stats->txholdreqcntr += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_TX_HOLD_REQ));
	stats->rxpacketassemblyerrcntr += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_PKT_ASSEMBLY_ERR));
	stats->rxpacketsmderrcntr += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_PKT_SMD_ERR));
	stats->rxpacketassemblyokcntr += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_PKT_ASSEMBLY_OK));
	stats->rxfpefragmentcntr += rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MMC_RX_FPE_FRAG));
}

static int
t2h_eqos_xstats_get(struct rte_eth_dev *dev, struct rte_eth_xstat *xstats, unsigned int n)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	unsigned int i;

	if (n < T2H_EQOS_XSTATS_COUNT) {
		return T2H_EQOS_XSTATS_COUNT;
	}

	/* MMC registers are configured for reset on read */
	t2h_eqos_read_mmc_stats(priv);

	for (i = 0; i < T2H_EQOS_XSTATS_COUNT; i++) {
		xstats[i].id	= i;
		xstats[i].value = *(uint64_t *)((uint8_t *)&priv->mmc_stats +
						t2h_eqos_xstats_strings[i].offset);
	}

	return T2H_EQOS_XSTATS_COUNT;
}

static int
t2h_eqos_xstats_get_by_id(struct rte_eth_dev *dev, const uint64_t *ids, uint64_t *values,
			  unsigned int n)
{
	unsigned int i;
	uint64_t values_copy[T2H_EQOS_XSTATS_COUNT];

	if (!ids) {
		struct renesas_t2h_private *priv = dev->data->dev_private;
		if (n < T2H_EQOS_XSTATS_COUNT) {
			return T2H_EQOS_XSTATS_COUNT;
		}

		t2h_eqos_read_mmc_stats(priv);

		for (i = 0; i < T2H_EQOS_XSTATS_COUNT; i++) {
			values[i] = *(uint64_t *)((uint8_t *)&priv->mmc_stats +
						  t2h_eqos_xstats_strings[i].offset);
		}

		return i;
	}

	t2h_eqos_xstats_get_by_id(dev, NULL, (void *)values_copy, T2H_EQOS_XSTATS_COUNT);

	for (i = 0; i < n; i++) {
		if (ids[i] >= T2H_EQOS_XSTATS_COUNT) {
			T2H_EQOS_PMD_ERR("Get Xstats Count Error");
			return -1;
		}
		values[i] = values_copy[ids[i]];
	}

	return n;
}

static int
t2h_eqos_xstats_get_names(__rte_unused struct rte_eth_dev *dev,
			  struct rte_eth_xstat_name *xstats_names, unsigned int n)
{
	unsigned int i;

	if (n >= T2H_EQOS_XSTATS_COUNT && xstats_names) {
		for (i = 0; i < T2H_EQOS_XSTATS_COUNT; ++i) {
			snprintf(xstats_names[i].name, RTE_ETH_XSTATS_NAME_SIZE, "%s",
				 t2h_eqos_xstats_strings[i].name);
		}
	}

	return T2H_EQOS_XSTATS_COUNT;
}

static int
t2h_eqos_xstats_get_names_by_id(struct rte_eth_dev *dev, const uint64_t *ids,
				struct rte_eth_xstat_name *xstats_names, unsigned int size)
{
	struct rte_eth_xstat_name xstats_names_copy[T2H_EQOS_XSTATS_COUNT];
	unsigned int i;

	if (!ids)
		return t2h_eqos_xstats_get_names(dev, xstats_names, size);

	t2h_eqos_xstats_get_names(dev, xstats_names_copy, size);

	for (i = 0; i < size; i++) {
		if (ids[i] >= T2H_EQOS_XSTATS_COUNT) {
			T2H_EQOS_PMD_ERR("id value isn't valid");
			return -1;
		}
		strcpy(xstats_names[i].name, xstats_names_copy[ids[i]].name);
	}

	return size;
}

static int
t2h_eqos_xstats_reset(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	struct t2h_eqos_mmc_stats *stats = &priv->mmc_stats;

	/* MMC registers are configured for reset on read */
	t2h_eqos_read_mmc_stats(priv);

	/* Reset stats */
	memset(stats, 0, sizeof(*stats));

	return 0;
}

static void
t2h_eqos_rxq_info_get(struct rte_eth_dev *dev, uint16_t queue_id, struct rte_eth_rxq_info *qinfo)
{
	struct t2h_eqos_priv_rx_q *rxq;

	rxq		   = dev->data->rx_queues[queue_id];
	qinfo->mp	   = rxq->mb_pool;
	qinfo->nb_desc	   = rxq->nb_rx_desc;
	qinfo->queue_state = rxq->queue_state;
}

static void
t2h_eqos_txq_info_get(struct rte_eth_dev *dev, uint16_t queue_id, struct rte_eth_txq_info *qinfo)
{
	struct t2h_eqos_priv_tx_q *txq;

	txq		   = dev->data->tx_queues[queue_id];
	qinfo->nb_desc	   = txq->nb_tx_desc;
	qinfo->queue_state = txq->queue_state;
}

static const struct eth_dev_ops t2h_eqos_ops = {
	.mtu_set		  = t2h_eqos_mtu_set,
	.dev_configure		  = t2h_eqos_eth_configure,
	.dev_start		  = t2h_eqos_eth_start,
	.dev_stop		  = t2h_eqos_eth_stop,
	.dev_close		  = t2h_eqos_eth_close,
	.rx_queue_setup		  = t2h_eqos_rx_queue_setup,
	.rx_queue_release	  = t2h_eqos_rx_queue_release,
	.tx_queue_setup		  = t2h_eqos_tx_queue_setup,
	.tx_queue_release	  = t2h_eqos_tx_queue_release,
	.promiscuous_enable	  = t2h_eqos_promiscuous_enable,
	.promiscuous_disable	  = t2h_eqos_promiscuous_disable,
	.allmulticast_enable	  = t2h_eqos_multicast_enable,
	.allmulticast_disable	  = t2h_eqos_allmulticast_disable,
	.mac_addr_set		  = t2h_eqos_set_mac_addr,
	.mac_addr_add		  = t2h_eqos_add_mac_addr,
	.mac_addr_remove	  = t2h_eqos_remove_mac_addr,
	.set_mc_addr_list	  = t2h_eqos_set_mc_addr_list,
	.vlan_filter_set	  = t2h_eqos_vlan_filter_set,
	.vlan_offload_set	  = t2h_eqos_vlan_offload_set,
	.dev_infos_get		  = t2h_eqos_eth_info,
	.get_reg		  = t2h_eqos_get_regs,
	.link_update		  = t2h_eqos_eth_link_update,
	.stats_get		  = t2h_eqos_stats_get,
	.dev_supported_ptypes_get = t2h_eqos_supported_ptypes_get,
	.stats_reset		  = t2h_eqos_stats_reset,
	.xstats_get		  = t2h_eqos_xstats_get,
	.xstats_get_by_id	  = t2h_eqos_xstats_get_by_id,
	.xstats_get_names	  = t2h_eqos_xstats_get_names,
	.xstats_get_names_by_id	  = t2h_eqos_xstats_get_names_by_id,
	.xstats_reset		  = t2h_eqos_xstats_reset,
	.rxq_info_get		  = t2h_eqos_rxq_info_get,
	.txq_info_get		  = t2h_eqos_txq_info_get};

static int
t2h_eqos_eth_init(struct rte_eth_dev *dev)
{
	dev->dev_ops = &t2h_eqos_ops;
	rte_eth_dev_probing_finish(dev);

	return 0;
}

static int
t2h_eqos_get_num_vlan(struct renesas_t2h_private *priv)
{
	uint32_t value, num;

	value = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_HW_FEATURE3));
	T2H_EQOS_PMD_DEBUG("The current MAC_HW_Feature3 is 0x%x", value);

	if ((value & T2H_EQOS_MAC_HW_FEAT3_NRVF) == 0) {
		num = T2H_EQOS_VLAN_DEF_NUM;
	} else if ((value & T2H_EQOS_MAC_HW_FEAT3_NRVF) == 1) {
		num = T2H_EQOS_VLAN_DEF_NUM_4;
	} else if ((value & T2H_EQOS_MAC_HW_FEAT3_NRVF) == 2) {
		num = T2H_EQOS_VLAN_DEF_NUM_8;
	} else if ((value & T2H_EQOS_MAC_HW_FEAT3_NRVF) == 3) {
		num = T2H_EQOS_VLAN_DEF_NUM_16;
	} else if ((value & T2H_EQOS_MAC_HW_FEAT3_NRVF) == 4) {
		num = T2H_EQOS_VLAN_DEF_NUM_24;
	} else if ((value & T2H_EQOS_MAC_HW_FEAT3_NRVF) == 5) {
		num = T2H_EQOS_VLAN_DEF_NUM_32;
	} else {
		num = T2H_EQOS_VLAN_DEF_NUM;
	}

	return num;
}

static int
pmd_t2h_eqos_probe(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *dev = NULL;
	struct renesas_t2h_private *priv;
	const char *name;
	int ret = 0;
	int i;
	uint32_t bdsize;
	uint32_t hw_cap;
	struct rte_ether_addr macaddr;
	void *addr_v;
	uint32_t addr_p;
	uint32_t version;
	uint32_t devname_length;
	char last_char;

	name = rte_vdev_device_name(vdev);
	T2H_EQOS_PMD_INFO("Probe device name: %s", name);

	dev = rte_eth_vdev_allocate(vdev, sizeof(*priv));
	if (dev == NULL) {
		T2H_EQOS_PMD_ERR("Failed to allocate mem %d to store MAC addresses",
				 RTE_ETHER_ADDR_LEN);
		return -ENOMEM;
	}

	devname_length = strlen(name);
	if (devname_length == 0 || name == NULL) {
		T2H_EQOS_PMD_ERR("Device Name is NULL");
		return -ENOMEM;
	}
	last_char = name[devname_length - 1];
	if (!isdigit(last_char)) {
		T2H_EQOS_PMD_ERR("Device Name Error");
		return -ENOMEM;
	}

	/* Allocate interrupt instance for pci device */
	dev->intr_handle = rte_intr_instance_alloc(RTE_INTR_INSTANCE_F_PRIVATE);
	if (dev->intr_handle == NULL) {
		T2H_EQOS_PMD_ERR("Failed to create interrupt instance");
		return -ENOMEM;
	}

	/* setup board info structure */
	priv	  = dev->data->dev_private;
	priv->dev = dev;

	priv->phy_reg = last_char - '0';

	priv->max_rx_queues = T2H_EQOS_MAX_Q;
	priv->max_tx_queues = T2H_EQOS_MAX_Q;

	ret = t2h_eqos_uio_configure(priv->phy_reg);
	if (ret != 0) {
		T2H_EQOS_PMD_ERR("UIO configure error: %d", ret);
		return -ENOMEM;
	}

	ret = config_t2h_eqos_uio(priv);
	if (ret != 0) {
		T2H_EQOS_PMD_ERR("T2H device configure error: %d", ret);
		return -ENOMEM;
	}

	rte_intr_fd_set(dev->intr_handle, priv->uio_fd);
	rte_intr_type_set(dev->intr_handle, RTE_INTR_HANDLE_UIO);

	T2H_EQOS_PMD_INFO("UIO config success priv->hw_baseaddr_v = %p", priv->hw_baseaddr_v);
	/* Get the BD size for distributing among sixteen queues */
	bdsize = (priv->bd_size) / T2H_EQOS_NUM_OF_BD_QUEUES;
	addr_v = priv->bd_addr_v;
	addr_p = priv->bd_addr_p;

	for (i = 0; i < priv->max_tx_queues; i++) {
		priv->dma_baseaddr_t[i] = addr_v;
		priv->bd_addr_p_t[i]    = addr_p;
		addr_v                  = (uint8_t *)addr_v + bdsize;
		addr_p                  = addr_p + bdsize;
		T2H_EQOS_PMD_INFO("priv->bd_addr_p_t[%d] = 0x%x  dma_baseaddr_t =0x%p", i,
				  priv->bd_addr_p_t[i], priv->dma_baseaddr_t[i]);
	}

	for (i = 0; i < priv->max_rx_queues; i++) {
		priv->dma_baseaddr_r[i] = addr_v;
		priv->bd_addr_p_r[i]    = addr_p;
		addr_v                  = (uint8_t *)addr_v + bdsize;
		addr_p                  = addr_p + bdsize;
		T2H_EQOS_PMD_INFO("priv->bd_addr_p_r[%d] = 0x%x", i, priv->bd_addr_p_r[i]);
	}

	if (!priv->dma_tx_size)
		priv->dma_tx_size = T2H_EQOS_DMA_DEF_TX_SIZE;
	if (!priv->dma_rx_size)
		priv->dma_rx_size = T2H_EQOS_DMA_DEF_RX_SIZE;

	/* Copy the station address into the dev structure */
	dev->data->mac_addrs =
		rte_zmalloc("mac_addr", RTE_ETHER_ADDR_LEN * T2H_EQOS_MAX_MAC_ADDR, 0);
	if (dev->data->mac_addrs == NULL) {
		T2H_EQOS_PMD_ERR("Failed to allocate mem %d to store MAC addresses",
				 RTE_ETHER_ADDR_LEN);
		ret = -ENOMEM;
		goto err;
	}

	dev->data->dev_flags |= RTE_ETH_DEV_INTR_LSC;

	/* Set default mac address */
	t2h_eqos_get_mac_addr(priv, &macaddr);
	if (!rte_is_valid_assigned_ether_addr(&macaddr)) {
		rte_eth_random_addr(macaddr.addr_bytes);
		t2h_eqos_set_mac_addr(dev, &macaddr);
	} else {
		rte_ether_addr_copy(&macaddr, &dev->data->mac_addrs[0]);
	}

	/* get vlan num */
	priv->vlan_num = t2h_eqos_get_num_vlan(priv);
	/* get vlhash */
	hw_cap = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_HW_FEATURE0));

	priv->vlhash = (hw_cap & T2H_EQOS_MAC_HW_FEAT0_VLHASH) >> T2H_EQOS_HW_FEAT0_VLHASH_SHIFT;

	/* MAC HW feature1 */
	hw_cap = rte_le_to_cpu_32(
		rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_HW_FEATURE1));

	/* Get size from Feature1 */
	priv->tx_fifo_size = T2H_EQOS_HW_FEAT1_FIFOSIZE_MASK
			     << ((hw_cap & T2H_EQOS_MAC_HW_FEAT1_TXFIFOSIZE) >>
				 T2H_EQOS_HW_FEAT1_TXFIFOSIZE_SHIFT);
	priv->rx_fifo_size = T2H_EQOS_HW_FEAT1_FIFOSIZE_MASK
			     << ((hw_cap & T2H_EQOS_MAC_HW_FEAT1_RXFIFOSIZE) >>
				 T2H_EQOS_HW_FEAT1_RXFIFOSIZE_SHIFT);
	priv->hash_tb_sz =
		(hw_cap & T2H_EQOS_MAC_HW_FEAT1_HASH_TB_SZ) >> T2H_EQOS_HW_FEAT1_HASH_TB_SZ_SHIFT;
	priv->rx_queues_to_use = T2H_EQOS_MAX_Q;
	priv->tx_queues_to_use = T2H_EQOS_MAX_Q;

	/* MAC VERSION */
	version =
		rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_MAC_VERSION));
	priv->version_id = (version & T2H_EQOS_MAC_DEFINED_VERSION);

	priv->d_size	  = sizeof(struct t2h_bufdesc);
	priv->d_size_log2 = t2h_eqos_fls64(priv->d_size);

	ret = t2h_eqos_eth_init(dev);
	if (ret) {
		T2H_EQOS_PMD_ERR("T2H device initialize error: %d", ret);
		goto failed_init;
	}

	T2H_EQOS_PMD_INFO("Probe device name: %s finished", name);
	return 0;

failed_init:
	T2H_EQOS_PMD_ERR("Failed to init");
err:
	rte_eth_dev_release_port(dev);
	return ret;
}

static int
pmd_t2h_eqos_remove(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *eth_dev = NULL;
	int ret			    = 0;
	const char *name;

	name = rte_vdev_device_name(vdev);
	T2H_EQOS_PMD_INFO("Remove device name: %s", name);

	/* find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(vdev));
	if (eth_dev == NULL) {
		T2H_EQOS_PMD_WARN("Device port already released!");
		/* port already released */
		return 0;
	}

	ret = t2h_eqos_eth_close(eth_dev);
	if (ret != 0) {
		T2H_EQOS_PMD_WARN("Close device failed: %d!", ret);
	}

	/* Release network device */
	ret = rte_eth_dev_release_port(eth_dev);
	if (ret != 0) {
		T2H_EQOS_PMD_WARN("Release device port failed: %d!", ret);
		return -EINVAL;
	}

	T2H_EQOS_PMD_INFO("Release port success and Remove T2H EQOS device finish");

	return ret;
}

static struct rte_vdev_driver pmd_t2h_eqos_drv = {
	.probe	= pmd_t2h_eqos_probe,
	.remove = pmd_t2h_eqos_remove,
};

RTE_PMD_REGISTER_VDEV(T2H_EQOS_NAME_PMD, pmd_t2h_eqos_drv);
RTE_LOG_REGISTER_DEFAULT(t2h_eqos_logtype_pmd, NOTICE);
