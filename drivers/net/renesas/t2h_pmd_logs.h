/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Renesas Electronics Corporation
 */

#ifndef _T2H_PMD_LOGS_H_
#define _T2H_PMD_LOGS_H_

#include <rte_log.h>

extern int t2h_eqos_logtype_pmd;

/* PMD related logs */
#define T2H_EQOS_PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_##level, t2h_eqos_logtype_pmd, "\nt2h_net: %s()" fmt "\n", __func__, ##args)

#if T2H_DEBUG
#define PMD_INIT_FUNC_TRACE()                   T2H_EQOS_PMD_LOG(DEBUG, " >>")
#define T2H_EQOS_PMD_DEBUG(fmt, args...)        T2H_EQOS_PMD_LOG(DEBUG, fmt, ##args)
#else
#define PMD_INIT_FUNC_TRACE()
#define T2H_EQOS_PMD_DEBUG(fmt, args...)
#endif
#define T2H_EQOS_PMD_INFO(fmt, args...)         T2H_EQOS_PMD_LOG(INFO, fmt, ##args)
#define T2H_EQOS_PMD_WARN(fmt, args...)         T2H_EQOS_PMD_LOG(WARNING, fmt, ##args)
#define T2H_EQOS_PMD_ERR(fmt, args...)	        T2H_EQOS_PMD_LOG(ERR, fmt, ##args)

/* DP Logs, toggled out at compile time if level lower than current level */
#define T2H_EQOS_DP_LOG(level, fmt, args...) RTE_LOG_DP(level, PMD, fmt, ##args)

#endif /* _T2H_PMD_LOGS_H_ */
