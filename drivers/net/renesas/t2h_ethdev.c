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

static int
t2h_eqos_eth_close(struct rte_eth_dev *dev)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;

	t2h_eqos_uio_cleanup(priv);

	rte_intr_dev_fd_set(dev->intr_handle, -1);
	rte_intr_instance_free(dev->intr_handle);
	dev->intr_handle = NULL;

	return 0;
}

static const struct eth_dev_ops t2h_eqos_ops = {
	.dev_close		  = t2h_eqos_eth_close
};

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

	name = rte_vdev_device_name(vdev);
	T2H_EQOS_PMD_INFO("Probe device name: %s", name);

	dev = rte_eth_vdev_allocate(vdev, sizeof(*priv));
	if (dev == NULL) {
		T2H_EQOS_PMD_ERR("Failed to allocate mem %d to store MAC addresses",
				 RTE_ETHER_ADDR_LEN);
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

	priv->max_rx_queues = T2H_EQOS_MAX_Q;
	priv->max_tx_queues = T2H_EQOS_MAX_Q;

	ret = t2h_eqos_uio_configure();
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
