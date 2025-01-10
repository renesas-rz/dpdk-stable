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

static const struct eth_dev_ops t2h_eqos_ops = {
	.dev_close		  = t2h_eqos_eth_close,
	.promiscuous_enable	  = t2h_eqos_promiscuous_enable,
	.promiscuous_disable	  = t2h_eqos_promiscuous_disable,
	.allmulticast_enable	  = t2h_eqos_multicast_enable,
	.allmulticast_disable	  = t2h_eqos_allmulticast_disable,
	.mac_addr_set		  = t2h_eqos_set_mac_addr,
	.mac_addr_add		  = t2h_eqos_add_mac_addr,
	.mac_addr_remove	  = t2h_eqos_remove_mac_addr,
	.set_mc_addr_list	  = t2h_eqos_set_mc_addr_list,
	.vlan_filter_set	  = t2h_eqos_vlan_filter_set,
	.vlan_offload_set	  = t2h_eqos_vlan_offload_set};

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
