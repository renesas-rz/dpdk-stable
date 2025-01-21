/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Renesas Electronics Corporation
 */

#include <rte_mbuf.h>
#include <rte_io.h>
#include <ethdev_driver.h>
#include <rte_malloc.h>

#include "t2h_pmd_logs.h"
#include "t2h_regs.h"
#include "t2h_ethdev.h"
#include "t2h_rxtx.h"

/* TDES2 descriptor (Rad Format) */
#define T2H_EQOS_TDES2_B1L                      GENMASK(13, 0)

/* RDES2 descriptor (Write-Back Format) */
#define T2H_EQOS_RDES2_SAF                      BIT(16)
#define T2H_EQOS_RDES2_DAF                      BIT(17)

/* TDES3 descriptor (Read Format) */
#define T2H_EQOS_TDES3_PACKET_SIZE              GENMASK(14, 0)
#define T2H_EQOS_TDES3_CIC_SHIFT                16

/* RDES1 descriptor (Write-Back Format) */
#define T2H_EQOS_RDES1_IPHE	                BIT(3)

/* RDES3 descriptor (Write-Back Format) */
#define T2H_EQOS_RDES3_PL                       GENMASK(14, 0)
#define T2H_EQOS_RDES3_ES                       BIT(15)
#define T2H_EQOS_RDES3_DE                       BIT(19)
#define T2H_EQOS_RDES3_RE                       BIT(20)
#define T2H_EQOS_RDES3_OE                       BIT(21)
#define T2H_EQOS_RDES3_GP                       BIT(23)
#define T2H_EQOS_RDES3_CE                       BIT(24)
#define T2H_EQOS_RDES3_CTXT                     BIT(30)

/* TDES3 descriptor (Write-Back Format) */
#define T2H_EQOS_TDES3_OWN                      BIT(31)
#define T2H_EQOS_TDES3_FD                       BIT(29)
#define T2H_EQOS_TDES3_LD                       BIT(28)
#define T2H_EQOS_TDES3_JT                       BIT(14)
#define T2H_EQOS_TDES3_FF                       BIT(13)
#define T2H_EQOS_TDES3_PCE                      BIT(12)
#define T2H_EQOS_TDES3_LOC                      BIT(11)
#define T2H_EQOS_TDES3_NC                       BIT(10)
#define T2H_EQOS_TDES3_LC                       BIT(9)
#define T2H_EQOS_TDES3_EC                       BIT(8)
#define T2H_EQOS_TDES3_ED                       BIT(3)
#define T2H_EQOS_TDES3_UF                       BIT(2)
#define T2H_EQOS_TDES3_IHE                      BIT(0)

/* RDES3 descriptor (Read Format) */
#define T2H_EQOS_RDES3_BUF1V                    BIT(24)
#define T2H_EQOS_RDES3_BUF2V                    BIT(25)
#define T2H_EQOS_RDES3_IOC                      BIT(30)

/* RDES3 descriptor (Read and Write Back) */
#define T2H_EQOS_RDES3_OWN                      BIT(31)

#define T2H_EQOS_FCS_LEN                        4

#define T2H_EQOS_TX_CIC_FULL                    3

#define T2H_EQOS_DEFAULT_DMA_PBL                8
#define T2H_EQOS_DMA_BUS_MODE_RPBL_SHIFT        16

#define T2H_EQOS_RXTX_DEF_NUM                   1
#define T2H_EQOS_RXTX_NUM_ZERO                  0

/* Rx Descriptor status */
enum t2h_eqos_rx_status {
	rx_des_good     = 0x0,
	rx_des_error    = 0x1,
	rx_des_own      = 0x2,
};

/* Tx Descriptor status */
enum t2h_eqos_tx_status {
	tx_des_done     = 0x0,
	tx_des_not_last = 0x1,
	tx_des_err      = 0x2,
	tx_des_own      = 0x4,
};

static __rte_always_inline uint32_t
rte_read32_no_rmb(const volatile void *addr)
{
	uint32_t val;

	val = rte_read32_relaxed(addr);
	return val;
}

static int
t2h_eqos_rx_status(struct t2h_bufdesc *p, struct rte_eth_stats *stats, uint32_t *len)
{
	uint32_t rdes3 = rte_le_to_cpu_32(rte_read32_no_rmb(&p->des3));
	int ret	       = rx_des_good;

	if (unlikely(rdes3 & T2H_EQOS_RDES3_OWN))
		return rx_des_own;

	*len = rdes3 & T2H_EQOS_RDES3_PL;

	if (unlikely(rdes3 & T2H_EQOS_RDES3_CTXT))
		return rx_des_error;

	if (unlikely(rdes3 & T2H_EQOS_RDES3_ES)) {
		if (unlikely(rdes3 & T2H_EQOS_RDES3_GP) || unlikely(rdes3 & T2H_EQOS_RDES3_CE) ||
		    unlikely(rdes3 & T2H_EQOS_RDES3_RE) || unlikely(rdes3 & T2H_EQOS_RDES3_OE) ||
		    unlikely(rdes3 & T2H_EQOS_RDES3_DE)) {
			stats->ierrors++;
		}

		ret = rx_des_error;
	}

	uint32_t rdes1 = rte_le_to_cpu_32(rte_read32_no_rmb(&p->des1));
	if (rdes1 & T2H_EQOS_RDES1_IPHE) {
		stats->ierrors++;
	}

	uint32_t rdes2 = rte_le_to_cpu_32(rte_read32_no_rmb(&p->des2));
	if (unlikely(rdes2 & T2H_EQOS_RDES2_SAF)) {
		stats->ierrors++;
		ret = rx_des_error;
	}
	if (unlikely(rdes2 & T2H_EQOS_RDES2_DAF)) {
		stats->ierrors++;
		ret = rx_des_error;
	}
	return ret;
}

static int
t2h_eqos_get_tx_status(struct t2h_bufdesc *p)
{
	uint32_t tdes3;
	int ret = tx_des_done;

	tdes3 = rte_le_to_cpu_32(rte_read32_no_rmb(&p->des3));

	/* Get OWN Status */
	if (unlikely(tdes3 & T2H_EQOS_TDES3_OWN)) {
		return tx_des_own;
	}

	/* Get LD Status */
	if (likely(!(tdes3 & T2H_EQOS_TDES3_LD))) {
		return tx_des_not_last;
	}

	if (unlikely(tdes3 & T2H_EQOS_TDES3_JT) || unlikely(tdes3 & T2H_EQOS_TDES3_FF) ||
	    unlikely(tdes3 & T2H_EQOS_TDES3_PCE) || unlikely(tdes3 & T2H_EQOS_TDES3_LOC) ||
	    unlikely(tdes3 & T2H_EQOS_TDES3_NC) || unlikely(tdes3 & T2H_EQOS_TDES3_ED) ||
	    unlikely(tdes3 & T2H_EQOS_TDES3_EC) || unlikely(tdes3 & T2H_EQOS_TDES3_LC) ||
	    unlikely(tdes3 & T2H_EQOS_TDES3_UF) || unlikely(tdes3 & T2H_EQOS_TDES3_IHE)) {
		return tx_des_err;
	}
	return ret;
}

static void
t2h_eqos_set_rx_owner(struct t2h_bufdesc *p, bool enable_rx_ic)
{
	uint32_t rdes3 = T2H_EQOS_RDES3_OWN | T2H_EQOS_RDES3_BUF1V;

	if (enable_rx_ic)
		rdes3 |= T2H_EQOS_RDES3_IOC;

	rte_write32(rte_cpu_to_le_32(rdes3), &p->des3);
}

static void
t2h_eqos_init_rx_desc(struct t2h_bufdesc *p, bool enable_rx_ic)
{
	t2h_eqos_set_rx_owner(p, enable_rx_ic);
}

static void
t2h_eqos_init_tx_desc(struct t2h_bufdesc *p)
{
	rte_write32(0, &p->des0);
	rte_write32(0, &p->des1);
	rte_write32(0, &p->des2);
	rte_write32(0, &p->des3);
}

static void
t2h_eqos_init_desc3(struct t2h_bufdesc *p)
{
	uint32_t des3 = rte_le_to_cpu_32(rte_read32(&p->des2));
	rte_write32(rte_cpu_to_le_32(des3 + T2H_EQOS_BUF_SIZE_8KB), &p->des3);
}

static void
t2h_eqos_prepare_tx_desc(struct t2h_bufdesc *p, int len, bool ls, uint32_t tot_pkt_len)
{
	rte_write32(rte_cpu_to_le_32(len & T2H_EQOS_TDES2_B1L), &p->des2);

	uint32_t tdes3 = tot_pkt_len & T2H_EQOS_TDES3_PACKET_SIZE;

	tdes3 |= T2H_EQOS_TDES3_FD;

	tdes3 &= ~(T2H_EQOS_TX_CIC_FULL << T2H_EQOS_TDES3_CIC_SHIFT);

	if (likely(ls))
		tdes3 |= T2H_EQOS_TDES3_LD;
	else
		tdes3 &= ~T2H_EQOS_TDES3_LD;

	tdes3 |= T2H_EQOS_TDES3_OWN;

	rte_write32(rte_cpu_to_le_32(tdes3), &p->des3);
}

static void
t2h_eqos_set_addr(struct t2h_bufdesc *p, uint64_t addr)
{
	rte_write32(rte_cpu_to_le_32(T2H_EQOS_LOWER_32_BITS(addr)), &p->des0);
	rte_write32(rte_cpu_to_le_32(T2H_EQOS_UPPER_32_BITS(addr)), &p->des1);
}

static void
t2h_eqos_set_sec_addr(struct t2h_bufdesc *p, uint64_t addr, bool buf2_addr_valid)
{
	uint32_t rdes2 = T2H_EQOS_LOWER_32_BITS(addr);
	uint32_t rdes3 = T2H_EQOS_UPPER_32_BITS(addr);

	if (buf2_addr_valid)
		rdes3 |= T2H_EQOS_RDES3_BUF2V;
	else
		rdes3 &= ~T2H_EQOS_RDES3_BUF2V;

	rte_write32(rte_cpu_to_le_32(rdes2), &p->des2);
	rte_write32(rte_cpu_to_le_32(rdes3), &p->des3);
}

void
t2h_qos_set_rx_tail_ptr(struct renesas_t2h_private *priv, uint32_t tail_ptr, uint32_t chan)
{
	rte_write32(rte_cpu_to_le_32(tail_ptr),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_END_ADDR(chan));
}

void
t2h_qos_set_tx_tail_ptr(struct renesas_t2h_private *priv, uint32_t tail_ptr, uint32_t chan)
{
	rte_write32(rte_cpu_to_le_32(tail_ptr),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_END_ADDR(chan));
}

static inline int
t2h_eqos_get_bd_index(struct t2h_bufdesc *bdp, struct t2h_eqos_priv_tx_q *txq)
{
	return ((const char *)bdp - (const char *)txq->tx_base) >> txq->priv->d_size_log2;
}

static inline struct t2h_bufdesc *
t2h_eqos_get_nextdesc(struct t2h_bufdesc *bdp, struct t2h_eqos_priv_tx_q *txq)
{
	return ((uintptr_t)bdp >= txq->tail_addr)
		       ? txq->tx_base
		       : (struct t2h_bufdesc *)(((uintptr_t)bdp) + txq->priv->d_size);
}

static void
t2h_eqos_rx_queue_release_mbufs(struct t2h_eqos_priv_rx_q *rxq)
{
	unsigned index = 0;

	if (rxq->sw_ring != NULL) {
		for (index = 0; index < rxq->nb_rx_desc; index++) {
			if (rxq->sw_ring[index].mbuf != NULL) {
				rte_pktmbuf_free_seg(rxq->sw_ring[index].mbuf);
				rxq->sw_ring[index].mbuf = NULL;
			}
		}
	}
}

void
t2h_eqos_release_rx_queue(struct t2h_eqos_priv_rx_q *rxq)
{
	if (rxq != NULL) {
		t2h_eqos_rx_queue_release_mbufs(rxq);
		rte_free(rxq->sw_ring);
		T2H_EQOS_PMD_DEBUG("free rx sw_ring");
		rxq->queue_state = RTE_ETH_QUEUE_STATE_STOPPED;
		rte_free(rxq);
		T2H_EQOS_PMD_DEBUG("free rxq");
	}
}

static void
t2h_eqos_tx_queue_release_mbufs(struct t2h_eqos_priv_tx_q *txq)
{
	unsigned i;

	if (txq->sw_ring != NULL) {
		for (i = 0; i < txq->nb_tx_desc; i++) {
			if (txq->sw_ring[i].mbuf != NULL) {
				rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf);
				txq->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

void
t2h_eqos_release_tx_queue(struct t2h_eqos_priv_tx_q *txq)
{
	if (txq != NULL) {
		t2h_eqos_tx_queue_release_mbufs(txq);
		rte_free(txq->sw_ring);
		T2H_EQOS_PMD_DEBUG("free tx sw_ring");
		txq->queue_state = RTE_ETH_QUEUE_STATE_STOPPED;
		rte_free(txq);
		T2H_EQOS_PMD_DEBUG("free txq");
	}
}

int
t2h_eqos_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc,
			uint32_t socket_id __rte_unused, const struct rte_eth_rxconf *rx_conf,
			struct rte_mempool *mp)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	struct t2h_eqos_priv_rx_q *rxq;
	uint32_t size;
	struct t2h_bufdesc *bd_base;

	/* Rx deferred start is not supported */
	if (rx_conf->rx_deferred_start) {
		T2H_EQOS_PMD_ERR("Rx deferred start not supported");
		return -EINVAL;
	}

	if (queue_idx >= T2H_EQOS_MAX_Q) {
		T2H_EQOS_PMD_ERR("Invalid queue id %d, max %d", queue_idx, T2H_EQOS_MAX_Q);
		return -EINVAL;
	}

	/* Free memory prior to re-allocation if needed */
	if (dev->data->rx_queues[queue_idx] != NULL) {
		t2h_eqos_release_rx_queue(dev->data->rx_queues[queue_idx]);
		dev->data->rx_queues[queue_idx] = NULL;
	}

	/* First allocate the RX queue data structure. */
	rxq = rte_zmalloc("T2H RX queue", sizeof(struct t2h_eqos_priv_rx_q), RTE_CACHE_LINE_SIZE);
	if (rxq == NULL) {
		T2H_EQOS_PMD_ERR("Allocate the RX queue failed!");
		return -ENOMEM;
	}

	rxq->mb_pool	= mp;
	rxq->nb_rx_desc = nb_desc;

	bd_base	    = (struct t2h_bufdesc *)priv->dma_baseaddr_r[queue_idx];
	rxq->dma_rx = bd_base;
	size	    = priv->d_size * rxq->nb_rx_desc;
	bd_base	    = (struct t2h_bufdesc *)(((uintptr_t)bd_base) + size);

	/* Allocate software ring. */
	rxq->sw_ring = rte_zmalloc("rxq->sw_ring", sizeof(struct t2h_eqos_rx_entry) * nb_desc,
				   RTE_CACHE_LINE_SIZE);
	if (rxq->sw_ring == NULL) {
		T2H_EQOS_PMD_ERR("Allocate software ring failed!");
		t2h_eqos_release_rx_queue(rxq);
		return -ENOMEM;
	}
	T2H_EQOS_PMD_INFO("sw_ring=%p queue_idx = %u ", rxq->sw_ring, queue_idx);
	struct rte_eth_stats *stats = &rxq->priv->stats;

	for (uint32_t i = 0; i < priv->dma_rx_size; i++) {
		struct t2h_bufdesc *p;
		p = (struct t2h_bufdesc *)(rxq->dma_rx + i);

		struct rte_mbuf *new_mbuf = rte_pktmbuf_alloc(rxq->mb_pool);
		if (unlikely(new_mbuf == NULL)) {
			stats->rx_nombuf++;
			break;
		}

		t2h_eqos_set_sec_addr(p, T2H_EQOS_RXTX_NUM_ZERO, false);

		rxq->sw_ring[i].mbuf = new_mbuf;
		t2h_eqos_set_addr(p, rte_pktmbuf_iova(new_mbuf));

		if (priv->buf_size == T2H_EQOS_BUF_SIZE_16KB) {
			t2h_eqos_init_desc3(p);
		}

		t2h_eqos_init_rx_desc(p, false);
	}

	rxq->cur       = 0;
	rxq->dirty     = 0;
	rxq->priv      = priv;
	rxq->queue_idx = queue_idx;
	rxq->tail_addr =
		(uintptr_t)priv->bd_addr_p_r[queue_idx] + (priv->dma_rx_size * priv->d_size);
	rxq->queue_state = RTE_ETH_QUEUE_STATE_STARTED;

	dev->data->rx_queues[queue_idx] = rxq;
	return 0;
}

void
t2h_eqos_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx)
{
	T2H_EQOS_PMD_DEBUG("queue_idx = %u", queue_idx);
	t2h_eqos_release_rx_queue(dev->data->rx_queues[queue_idx]);
	dev->data->rx_queues[queue_idx] = NULL;
}

int
t2h_eqos_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx, uint16_t nb_desc,
			uint32_t socket_id __rte_unused, const struct rte_eth_txconf *tx_conf)
{
	struct renesas_t2h_private *priv = dev->data->dev_private;
	struct t2h_bufdesc *bd_base;
	struct t2h_eqos_priv_tx_q *txq;
	uint32_t size;

	/* Tx deferred start is not supported */
	if (tx_conf->tx_deferred_start) {
		T2H_EQOS_PMD_ERR("Tx deferred start not supported");
		return -EINVAL;
	}

	if (queue_idx >= T2H_EQOS_MAX_Q) {
		T2H_EQOS_PMD_ERR("Invalid queue id %d, max %d", queue_idx, T2H_EQOS_MAX_Q);
		return -EINVAL;
	}

	/* Free memory prior to re-allocation if needed */
	T2H_EQOS_PMD_INFO("queue_idx = %u ", queue_idx);
	if (dev->data->tx_queues[queue_idx] != NULL) {
		t2h_eqos_release_tx_queue(dev->data->tx_queues[queue_idx]);
		dev->data->tx_queues[queue_idx] = NULL;
	}

	/* allocate transmit queue */
	txq = rte_zmalloc("T2H TX queue", sizeof(*txq), RTE_CACHE_LINE_SIZE);
	if (txq == NULL) {
		T2H_EQOS_PMD_ERR("transmit queue allocation failed");
		return -ENOMEM;
	}

	if (nb_desc > T2H_EQOS_MAX_TX_BD_RING_SIZE) {
		nb_desc = T2H_EQOS_MAX_TX_BD_RING_SIZE;
	}

	txq->nb_tx_desc = nb_desc;

	/* Set transmit descriptor base. */
	txq->priv      = priv;
	txq->queue_idx = queue_idx;

	bd_base	     = (struct t2h_bufdesc *)priv->dma_baseaddr_t[queue_idx];
	txq->tx_base = bd_base;
	txq->cur     = 0;
	size	     = priv->d_size * txq->nb_tx_desc;

	bd_base	       = (struct t2h_bufdesc *)(((uintptr_t)bd_base) + size);
	txq->tail_addr = (uintptr_t)priv->bd_addr_p_t[queue_idx];

	/* Allocate software ring */
	txq->sw_ring = rte_zmalloc("txq->sw_ring", sizeof(struct t2h_eqos_tx_entry) * nb_desc,
				   RTE_CACHE_LINE_SIZE);
	if (txq->sw_ring == NULL) {
		T2H_EQOS_PMD_ERR("Allocate software ring failed!");
		t2h_eqos_release_tx_queue(txq);
		return -ENOMEM;
	}

	for (uint32_t i = 0; i < txq->nb_tx_desc; i++) {
		struct t2h_bufdesc *p;
		p = (struct t2h_bufdesc *)txq->tx_base + i;
		if (txq->sw_ring != NULL) {
			if (txq->sw_ring[i].mbuf != NULL) {
				rte_pktmbuf_free(txq->sw_ring[i].mbuf);
				txq->sw_ring[i].mbuf = NULL;
			}
		}

		t2h_eqos_init_tx_desc(p);
	}
	txq->queue_state		= RTE_ETH_QUEUE_STATE_STARTED;
	dev->data->tx_queues[queue_idx] = txq;
	return 0;
}

void
t2h_eqos_tx_queue_release(struct rte_eth_dev *dev, uint16_t queue_idx)
{
	T2H_EQOS_PMD_DEBUG("queue_idx = %u ", queue_idx);
	t2h_eqos_release_tx_queue(dev->data->tx_queues[queue_idx]);
	dev->data->tx_queues[queue_idx] = NULL;
}

void
t2h_eqos_free_all_queues(struct rte_eth_dev *dev)
{
	uint32_t i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		T2H_EQOS_PMD_DEBUG("rx_queue = %u ", i);
		if (dev->data->rx_queues[i] != NULL) {
			t2h_eqos_release_rx_queue(dev->data->rx_queues[i]);
			dev->data->rx_queues[i] = NULL;
		}
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		T2H_EQOS_PMD_DEBUG("tx_queue = %u ", i);
		if (dev->data->tx_queues[i] != NULL) {
			t2h_eqos_release_tx_queue(dev->data->tx_queues[i]);
			dev->data->tx_queues[i] = NULL;
		}
	}
}

static inline uint32_t
t2h_eqos_rx_index(struct t2h_eqos_priv_rx_q *rx_q)
{
	uint32_t idx;

	if (rx_q->dirty <= rx_q->cur)
		idx = rx_q->cur - rx_q->dirty;
	else
		idx = rx_q->priv->dma_rx_size - rx_q->dirty + rx_q->cur;
	return idx;
}

void
t2h_eqos_init_rx_chan(struct renesas_t2h_private *priv, struct t2h_eqos_priv_rx_q *rxq)
{
	uint32_t value;
	uint32_t rxpbl = T2H_EQOS_DEFAULT_DMA_PBL;

	value = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
					    T2H_EQOS_DMA_CH_RX_CTRL(rxq->queue_idx)));

	value |= (rxpbl << T2H_EQOS_DMA_BUS_MODE_RPBL_SHIFT);
	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_CTRL(rxq->queue_idx));

	rte_write32(rte_cpu_to_le_32(priv->bd_addr_p_r[rxq->queue_idx]),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_RX_BASE_ADDR(rxq->queue_idx));

	t2h_qos_set_rx_tail_ptr(priv, rxq->tail_addr, rxq->queue_idx);
}

void
t2h_eqos_init_tx_chan(struct renesas_t2h_private *priv, struct t2h_eqos_priv_tx_q *txq)
{
	uint32_t value;
	uint32_t txpbl = T2H_EQOS_DEFAULT_DMA_PBL;

	value = rte_le_to_cpu_32(rte_read32((uint8_t *)priv->hw_baseaddr_v +
					    T2H_EQOS_DMA_CH_TX_CTRL(txq->queue_idx)));

	value |= (txpbl << T2H_EQOS_DMA_BUS_MODE_RPBL_SHIFT);

	/* Operate on Second Packet enabled */
	value |= T2H_EQOS_DMA_CH_TX_CTRL_OSP;

	rte_write32(rte_cpu_to_le_32(value),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_CTRL(txq->queue_idx));

	rte_write32(rte_cpu_to_le_32(priv->bd_addr_p_t[txq->queue_idx]),
		    (uint8_t *)priv->hw_baseaddr_v + T2H_EQOS_DMA_CH_TX_BASE_ADDR(txq->queue_idx));

	t2h_qos_set_tx_tail_ptr(priv, txq->tail_addr, txq->queue_idx);
}

static inline void
t2h_eqos_rx_refill(struct t2h_eqos_priv_rx_q *rx_q, uint32_t queue_index)
{
	struct renesas_t2h_private *priv = rx_q->priv;
	uint32_t idx			 = t2h_eqos_rx_index(rx_q);
	uint32_t cur			 = rx_q->dirty;
	struct rte_eth_stats *stats	 = &rx_q->priv->stats;

	while (idx-- > 0) {
		struct t2h_bufdesc *p;

		p = (struct t2h_bufdesc *)(rx_q->dma_rx + cur);
		rte_prefetch0(p);

		if (likely(!rx_q->sw_ring[cur].mbuf)) {
			struct rte_mbuf *new_mbuf = rte_pktmbuf_alloc(rx_q->mb_pool);
			if (unlikely(new_mbuf == NULL)) {
				stats->rx_nombuf++;
				continue;
			}

			rx_q->sw_ring[cur].mbuf = new_mbuf;
			t2h_eqos_set_addr(p, rte_pktmbuf_iova(new_mbuf));

			t2h_eqos_set_sec_addr(p, T2H_EQOS_RXTX_NUM_ZERO, false);

			if (priv->buf_size == T2H_EQOS_BUF_SIZE_16KB) {
				t2h_eqos_init_desc3(p);
			}
		}
		rte_wmb();

		t2h_eqos_set_rx_owner(p, false);
		cur = ((cur + T2H_EQOS_RXTX_DEF_NUM) & (priv->dma_rx_size - T2H_EQOS_RXTX_DEF_NUM));
	}
	rx_q->dirty	= cur;
	rx_q->tail_addr = (uintptr_t)priv->bd_addr_p_r[queue_index] + (rx_q->dirty * priv->d_size);

	t2h_qos_set_rx_tail_ptr(priv, rx_q->tail_addr, queue_index);
}

uint16_t
t2h_eqos_recv_pkts(void *rxq1, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct t2h_eqos_priv_rx_q *rx_q  = (struct t2h_eqos_priv_rx_q *)rxq1;
	uint32_t next_mbuf               = rx_q->cur;
	struct renesas_t2h_private *priv = rx_q->priv;
	uint32_t count                   = 0;
	uint32_t max_recv_num            = 0;
	void *data;
	struct rte_eth_stats *stats = &rx_q->priv->stats;

	max_recv_num = (nb_pkts < priv->dma_rx_size) ? nb_pkts
						     : (priv->dma_rx_size - T2H_EQOS_RXTX_DEF_NUM);
	while (count < max_recv_num) {
		int cur_mbuf, status;
		uint32_t frame_len = 0;
		struct t2h_bufdesc *p;
		struct t2h_bufdesc *np;

		cur_mbuf = next_mbuf;

		p = (struct t2h_bufdesc *)(rx_q->dma_rx + cur_mbuf);

		/* Read the status and frame length */
		status = t2h_eqos_rx_status(p, stats, &frame_len);

		/* check the OWN bit */
		if (unlikely(status & rx_des_own)) {
			break;
		}

		count++;
		rx_q->cur = (rx_q->cur + T2H_EQOS_RXTX_DEF_NUM) &
			    (priv->dma_rx_size - T2H_EQOS_RXTX_DEF_NUM);
		next_mbuf = rx_q->cur;

		np = (struct t2h_bufdesc *)(rx_q->dma_rx + next_mbuf);

		rte_prefetch0(np);

		if (unlikely(status == rx_des_error)) {
			continue;
		} else {
			struct rte_mbuf *mbuf;
			stats->ipackets++;

			/* If frame length is greater than buffer size then the packet is ignored */
			if (frame_len > priv->buf_size) {
				T2H_EQOS_PMD_ERR("len %d larger than size (%d)", frame_len,
						 priv->dma_rx_size);
				continue;
			}

			if (priv->flag_csum && T2H_EQOS_MAC_CONFIG_CST) {
				frame_len -= T2H_EQOS_FCS_LEN;
			}
			stats->ibytes += frame_len;

			mbuf = rx_q->sw_ring[cur_mbuf].mbuf;
			if (unlikely(!mbuf)) {
				T2H_EQOS_PMD_ERR("memeory buffer(mbuf) is NULL");
				continue;
			}
			data = rte_pktmbuf_mtod(mbuf, uint8_t *);
			rte_prefetch0(data);

			rte_pktmbuf_append((struct rte_mbuf *)mbuf, frame_len);
			rx_q->sw_ring[cur_mbuf].mbuf = NULL;

			rx_pkts[count - T2H_EQOS_RXTX_DEF_NUM] = mbuf;
		}
	}

	t2h_eqos_rx_refill(rx_q, rx_q->queue_idx);
	return count;
}

uint16_t
t2h_eqos_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct t2h_eqos_priv_tx_q *txq   = (struct t2h_eqos_priv_tx_q *)tx_queue;
	struct renesas_t2h_private *priv = txq->priv;
	struct t2h_bufdesc *bdp, *last_bdp;
	struct rte_mbuf *mbuf;
	uint16_t buflen;
	uint32_t index = 0;
	uint32_t i, pkt_transmitted = 0;
	uint8_t *data;
	int tx_st                   = T2H_EQOS_RXTX_DEF_NUM;
	struct rte_eth_stats *stats = &txq->priv->stats;

	while (tx_st) {
		if (pkt_transmitted >= nb_pkts) {
			tx_st = 0;
			break;
		}

		mbuf = *(tx_pkts);
		if (mbuf->nb_segs > T2H_EQOS_RXTX_DEF_NUM) {
			T2H_EQOS_DP_LOG(DEBUG, "SG not supported");
			return pkt_transmitted;
		}

		tx_pkts++;
		bdp = (struct t2h_bufdesc *)(txq->tx_base + txq->cur);

		/* First clean the ring */
		index = t2h_eqos_get_bd_index(bdp, txq);

		int tx_status = t2h_eqos_get_tx_status(bdp);
		/* Check if the descriptor is owned by the DMA */
		if (unlikely(tx_status & tx_des_own)) {
			break;
		}
		if (txq->sw_ring[index].mbuf) {
			rte_pktmbuf_free(txq->sw_ring[index].mbuf);
			txq->sw_ring[index].mbuf = NULL;
		}

		if (likely(!(tx_status & tx_des_not_last))) {
			if (unlikely(tx_status & tx_des_err)) {
				stats->oerrors++;
			} else {
				stats->opackets++;
			}
		}

		/* Fill in a Tx ring entry */
		last_bdp = bdp;

		/* Set buffer length and buffer pointer */
		buflen = rte_pktmbuf_pkt_len(mbuf);
		stats->obytes += buflen;
		data = rte_pktmbuf_mtod(mbuf, void *);
		for (i = 0; i <= buflen; i += RTE_CACHE_LINE_SIZE)
			dcbf(data + i);

		/* set the descriptor */
		t2h_eqos_set_addr(bdp, rte_pktmbuf_iova(mbuf));
		t2h_eqos_prepare_tx_desc(bdp, buflen, (mbuf->nb_segs == T2H_EQOS_RXTX_DEF_NUM),
					 buflen);

		index = t2h_eqos_get_bd_index(last_bdp, txq);
		/* Save mbuf pointer */
		txq->sw_ring[index].mbuf = mbuf;

		/* Trigger transmission start */
		pkt_transmitted++;
		/* Make sure the update to bdp and tx_skbuff are performed before txq->head. */
		txq->cur = ((txq->cur + T2H_EQOS_RXTX_DEF_NUM) &
			    (priv->dma_tx_size - T2H_EQOS_RXTX_DEF_NUM));
	}
	if (pkt_transmitted != T2H_EQOS_RXTX_NUM_ZERO) {
		txq->tail_addr =
			(uintptr_t)priv->bd_addr_p_t[txq->queue_idx] + (txq->cur * priv->d_size);
		t2h_qos_set_tx_tail_ptr(priv, txq->tail_addr, txq->queue_idx);
	}
	return pkt_transmitted;
}
