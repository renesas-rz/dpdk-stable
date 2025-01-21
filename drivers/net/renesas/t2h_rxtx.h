/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Renesas Electronics Corporation
 */
#ifndef __T2H_RXTX_H__
#define __T2H_RXTX_H__

#include <rte_ethdev.h>

struct t2h_bufdesc {
	uint32_t des0;
	uint32_t des1;
	uint32_t des2;
	uint32_t des3;
};

struct t2h_eqos_rx_entry {
	/* mbuf associated with RX descriptor. */
	struct rte_mbuf *mbuf;
};

struct t2h_eqos_priv_rx_q {
	/* mbuf pool to populate RX ring. */
	struct rte_mempool *mb_pool;
	/* Basic rx descriptor addr */
	struct t2h_bufdesc *dma_rx;
	/* address of RX software ring. */
	struct t2h_eqos_rx_entry *sw_ring;
	/* number of RX descriptors. */
	uint16_t nb_rx_desc;
	/* RX queue index. */
	uint32_t queue_idx;
	uint32_t cur;
	uint32_t dirty;
	uint32_t tail_addr;
	struct renesas_t2h_private *priv;
	uint8_t queue_state;
};

struct t2h_eqos_tx_entry {
	/* mbuf associated with TX desc, if any. */
	struct rte_mbuf *mbuf;
};

struct t2h_eqos_priv_tx_q {
	/* mbuf pool to populate TX ring. */
	struct rte_mempool *mb_pool;
	/* Basic tx descriptor addr */
	struct t2h_bufdesc *tx_base;
	/* virtual address of SW ring. */
	struct t2h_eqos_tx_entry *sw_ring;
	/* number of TX descriptors. */
	uint16_t nb_tx_desc;
	/* TX queue index. */
	uint32_t queue_idx;
	/* Current value of TDT register. */
	uint32_t tail_addr;
	uint32_t cur;
	struct renesas_t2h_private *priv;
	uint8_t queue_state;
};

void t2h_qos_set_rx_tail_ptr(struct renesas_t2h_private *priv, uint32_t tail_ptr, uint32_t chan);
void t2h_qos_set_tx_tail_ptr(struct renesas_t2h_private *priv, uint32_t tail_ptr, uint32_t chan);

int t2h_eqos_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc,
			    uint32_t socket_id, const struct rte_eth_rxconf *rx_conf,
			    struct rte_mempool *mp);

void t2h_eqos_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx);

void t2h_eqos_release_rx_queue(struct t2h_eqos_priv_rx_q *rxq);

int t2h_eqos_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc,
			    uint32_t socket_id __rte_unused, const struct rte_eth_txconf *tx_conf);

void t2h_eqos_tx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx);

void t2h_eqos_release_tx_queue(struct t2h_eqos_priv_tx_q *txq);

void t2h_eqos_free_all_queues(struct rte_eth_dev *dev);

void t2h_eqos_init_rx_chan(struct renesas_t2h_private *priv, struct t2h_eqos_priv_rx_q *rxq);

void t2h_eqos_init_tx_chan(struct renesas_t2h_private *priv, struct t2h_eqos_priv_tx_q *txq);

uint16_t t2h_eqos_recv_pkts(void *rxq1, struct rte_mbuf **rx_pkts, uint16_t nb_pkts);

uint16_t t2h_eqos_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);

#endif /* __T2H_RXTX_H__ */
