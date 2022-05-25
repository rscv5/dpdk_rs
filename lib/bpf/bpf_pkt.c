/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include <sys/queue.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_atomic.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include <rte_bpf_ethdev.h>
#include "bpf_impl.h"

/*
 * information about installed BPF rx/tx callback
 */

struct bpf_eth_cbi {
	/* used by both data & control path */
	uint32_t use;    /*usage counter */
	const struct rte_eth_rxtx_callback *cb;  /* callback handle */
	struct rte_bpf *bpf;
	struct rte_bpf_jit jit;
	/* used by control path only */
	LIST_ENTRY(bpf_eth_cbi) link;
	uint16_t port;
	uint16_t queue;
} __rte_cache_aligned;

/*
 * Odd number means that callback is used by datapath.
 * Even number means that callback is not used by datapath.
 */
#define BPF_ETH_CBI_INUSE  1

/*
 * List to manage RX/TX installed callbacks.
 */
LIST_HEAD(bpf_eth_cbi_list, bpf_eth_cbi);

enum {
	BPF_ETH_RX,
	BPF_ETH_TX,
	BPF_ETH_NUM,
};

/*
 * information about all installed BPF rx/tx callbacks
 */
struct bpf_eth_cbh {
	rte_spinlock_t lock;
	struct bpf_eth_cbi_list list;
	uint32_t type;
};

static struct bpf_eth_cbh rx_cbh = {
	.lock = RTE_SPINLOCK_INITIALIZER,
	.list = LIST_HEAD_INITIALIZER(list),
	.type = BPF_ETH_RX,
};

static struct bpf_eth_cbh tx_cbh = {
	.lock = RTE_SPINLOCK_INITIALIZER,
	.list = LIST_HEAD_INITIALIZER(list),
	.type = BPF_ETH_TX,
};

/*
 * Marks given callback as used by datapath.
 */
static __rte_always_inline void
bpf_eth_cbi_inuse(struct bpf_eth_cbi *cbi)
{
	cbi->use++;
	/* make sure no store/load reordering could happen */
	rte_smp_mb();
}

/*
 * Marks given callback list as not used by datapath.
 */
static __rte_always_inline void
bpf_eth_cbi_unuse(struct bpf_eth_cbi *cbi)
{
	/* make sure all previous loads are completed */
	rte_smp_rmb();
	cbi->use++;
}

/*
 * Waits till datapath finished using given callback.
 */
static void
bpf_eth_cbi_wait(const struct bpf_eth_cbi *cbi)
{
	uint32_t puse;

	/* make sure all previous loads and stores are completed */
	rte_smp_mb();

	puse = cbi->use;

	/* in use, busy wait till current RX/TX iteration is finished */
	if ((puse & BPF_ETH_CBI_INUSE) != 0) {
		RTE_WAIT_UNTIL_MASKED((uint32_t *)(uintptr_t)&cbi->use,
			UINT32_MAX, !=, puse, __ATOMIC_RELAXED);
	}
}

static void
bpf_eth_cbi_cleanup(struct bpf_eth_cbi *bc)
{
	bc->bpf = NULL;
	memset(&bc->jit, 0, sizeof(bc->jit));
}

static struct bpf_eth_cbi *
bpf_eth_cbh_find(struct bpf_eth_cbh *cbh, uint16_t port, uint16_t queue)
{
	struct bpf_eth_cbi *cbi;

	LIST_FOREACH(cbi, &cbh->list, link) {
		if (cbi->port == port && cbi->queue == queue)
			break;
	}
	return cbi;
}

static struct bpf_eth_cbi *
bpf_eth_cbh_add(struct bpf_eth_cbh *cbh, uint16_t port, uint16_t queue)
{
	struct bpf_eth_cbi *cbi;

	/* return an existing one */
	cbi = bpf_eth_cbh_find(cbh, port, queue);
	if (cbi != NULL)
		return cbi;

	cbi = rte_zmalloc(NULL, sizeof(*cbi), RTE_CACHE_LINE_SIZE);
	if (cbi != NULL) {
		cbi->port = port;
		cbi->queue = queue;
		LIST_INSERT_HEAD(&cbh->list, cbi, link);
	}
	return cbi;
}

/*
 * BPF packet processing routines.
 */

static inline uint32_t
apply_filter(struct rte_mbuf *mb[], const uint64_t rc[], uint32_t num,
	uint32_t drop)
{
	uint32_t i, j, k;
	struct rte_mbuf *dr[num];

	for (i = 0, j = 0, k = 0; i != num; i++) {

		/* filter matches */
		if (rc[i] != 0)
			mb[j++] = mb[i];
		/* no match */
		else
			dr[k++] = mb[i];
	}

	if (drop != 0) {
		/* free filtered out mbufs */
		for (i = 0; i != k; i++)
			rte_pktmbuf_free(dr[i]);
	} else {
		/* copy filtered out mbufs beyond good ones */
		for (i = 0; i != k; i++)
			mb[j + i] = dr[i];
	}

	return j;
}

static inline uint32_t
pkt_filter_vm(const struct rte_bpf *bpf, struct rte_mbuf *mb[], uint32_t num,
	uint32_t drop)
{
	uint32_t i;
	void *dp[num];
	uint64_t rc[num];

	for (i = 0; i != num; i++)
		dp[i] = rte_pktmbuf_mtod(mb[i], void *);

	rte_bpf_exec_burst(bpf, dp, rc, num);
	return apply_filter(mb, rc, num, drop);
}

static inline uint32_t
pkt_filter_jit(const struct rte_bpf_jit *jit, struct rte_mbuf *mb[],
	uint32_t num, uint32_t drop)
{
	uint32_t i, n;
	void *dp;
	uint64_t rc[num]; // 是否丢包flag

	n = 0; // 统计丢包个数
	for (i = 0; i != num; i++) {
		dp = rte_pktmbuf_mtod(mb[i], void *); 
		rc[i] = jit->func(dp); // 调用entry 只能有一个参数？ 
		n += (rc[i] == 0);
	}

	if (n != 0)
		num = apply_filter(mb, rc, num, drop);

	return num;
}

//////////////////////////////////////////////////////////////////////////////////
// 1.
static inline uint32_t
pkt_test_jit(const struct rte_bpf_jit *jit, struct hash_mbuf *my_par,
         uint32_t num, uint32_t drop)
{
    uint32_t i, n;
    // void *dp;
    uint64_t rc[num];
    // char h_key[128];
    struct rte_mbuf **mb;  //  如果模仿pkt_filter_jit 设为 *mb[] 会报错 array size missing in mb

    mb = my_par->mbuf;
    // h_key = my_par->hash_key;

    // 循环遍历
    n = 0;
    for(i = 0; i != num; i++){
        // dp = my_par;
        rc[i] = jit->func(my_par);
        n += (rc[i] == 0);
    }
    
    if(n != 0)
        num = apply_filter(mb, rc, num, drop);
    
    return num;

}

//////////////////////////////////////////////////////////////////////////////
static inline uint32_t
pkt_filter_mb_vm(const struct rte_bpf *bpf, struct rte_mbuf *mb[], uint32_t num,
	uint32_t drop)
{
	uint64_t rc[num];

	rte_bpf_exec_burst(bpf, (void **)mb, rc, num);
	return apply_filter(mb, rc, num, drop);
}

static inline uint32_t
pkt_filter_mb_jit(const struct rte_bpf_jit *jit, struct rte_mbuf *mb[],
	uint32_t num, uint32_t drop)
{
	uint32_t i, n;
	uint64_t rc[num];

	n = 0; // 丢包数量统计
	for (i = 0; i != num; i++) {
		rc[i] = jit->func(mb[i]); // entry 
		n += (rc[i] == 0);
	}

	if (n != 0)
		num = apply_filter(mb, rc, num, drop); // 丢包过滤

	return num;
}

/*
 * RX/TX callbacks for raw data bpf.
 */

static uint16_t
bpf_rx_callback_vm(__rte_unused uint16_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param)
{
	struct bpf_eth_cbi *cbi;
	uint16_t rc;

	cbi = user_param;

	bpf_eth_cbi_inuse(cbi);
	rc = (cbi->cb != NULL) ?
		pkt_filter_vm(cbi->bpf, pkt, nb_pkts, 1) :
		nb_pkts;
	bpf_eth_cbi_unuse(cbi);
	return rc;
}

static uint16_t
bpf_rx_callback_jit(__rte_unused uint16_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param)
{
	struct bpf_eth_cbi *cbi; // information about installed BPF rx/tx callback
	uint16_t rc;  // 

	cbi = user_param; 
	bpf_eth_cbi_inuse(cbi); //  marks given callback as used by datapath
	rc = (cbi->cb != NULL) ? 
		pkt_filter_jit(&cbi->jit, pkt, nb_pkts, 1) :
		nb_pkts;
	bpf_eth_cbi_unuse(cbi);
	return rc;
}

///////////////////////////////////////////////////////////////////////
// 2. 
static uint16_t
bpf_rx_callback_jit_test(__rte_unused uint16_t port, __rte_unused uint16_t queue,
    //struct rte_mbuf *pkt[], 
    uint16_t nb_pkts, struct hash_mbuf *my_par,
    __rte_unused uint16_t max_pkts, void *user_param)
{
    struct bpf_eth_cbi *cbi; // information about
    uint16_t rc; 

    cbi = user_param;
    bpf_eth_cbi_inuse(cbi); // marks given callback as used by datapath
    rc = (cbi->cb != NULL) ?
        pkt_test_jit(&cbi->jit, my_par, nb_pkts, 0):
        nb_pkts;
    bpf_eth_cbi_unuse(cbi);
    return rc;
}

//////////////////////////////////////////////////////////////////////

static uint16_t
bpf_tx_callback_vm(__rte_unused uint16_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts, void *user_param)
{
	struct bpf_eth_cbi *cbi;
	uint16_t rc;

	cbi = user_param;
	bpf_eth_cbi_inuse(cbi);
	rc = (cbi->cb != NULL) ?
		pkt_filter_vm(cbi->bpf, pkt, nb_pkts, 0) :
		nb_pkts;
	bpf_eth_cbi_unuse(cbi);
	return rc;
}

static uint16_t
bpf_tx_callback_jit(__rte_unused uint16_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts, void *user_param)
{
	struct bpf_eth_cbi *cbi;
	uint16_t rc;

	cbi = user_param;
	bpf_eth_cbi_inuse(cbi);
	rc = (cbi->cb != NULL) ?
		pkt_filter_jit(&cbi->jit, pkt, nb_pkts, 0) :
		nb_pkts;
	bpf_eth_cbi_unuse(cbi);
	return rc;
}

/*
 * RX/TX callbacks for mbuf.
 */

static uint16_t
bpf_rx_callback_mb_vm(__rte_unused uint16_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param)
{
	struct bpf_eth_cbi *cbi;
	uint16_t rc;

	cbi = user_param;
	bpf_eth_cbi_inuse(cbi);
	rc = (cbi->cb != NULL) ?
		pkt_filter_mb_vm(cbi->bpf, pkt, nb_pkts, 1) :
		nb_pkts;
	bpf_eth_cbi_unuse(cbi);
	return rc;
}

static uint16_t
bpf_rx_callback_mb_jit(__rte_unused uint16_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts,
	__rte_unused uint16_t max_pkts, void *user_param)
{
	struct bpf_eth_cbi *cbi;
	uint16_t rc;

	cbi = user_param;
	bpf_eth_cbi_inuse(cbi);
	rc = (cbi->cb != NULL) ?
		pkt_filter_mb_jit(&cbi->jit, pkt, nb_pkts, 1) :
		nb_pkts;
	bpf_eth_cbi_unuse(cbi);
	return rc;
}

static uint16_t
bpf_tx_callback_mb_vm(__rte_unused uint16_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts, void *user_param)
{
	struct bpf_eth_cbi *cbi;
	uint16_t rc;

	cbi = user_param;
	bpf_eth_cbi_inuse(cbi);
	rc = (cbi->cb != NULL) ?
		pkt_filter_mb_vm(cbi->bpf, pkt, nb_pkts, 0) :
		nb_pkts;
	bpf_eth_cbi_unuse(cbi);
	return rc;
}

static uint16_t
bpf_tx_callback_mb_jit(__rte_unused uint16_t port, __rte_unused uint16_t queue,
	struct rte_mbuf *pkt[], uint16_t nb_pkts, void *user_param)
{
	struct bpf_eth_cbi *cbi;
	uint16_t rc;

	cbi = user_param;
	bpf_eth_cbi_inuse(cbi);
	rc = (cbi->cb != NULL) ?
		pkt_filter_mb_jit(&cbi->jit, pkt, nb_pkts, 0) :
		nb_pkts;
	bpf_eth_cbi_unuse(cbi);
	return rc;
}


// 返回回调函数指针
static rte_rx_callback_fn
select_rx_callback(enum rte_bpf_arg_type type, uint32_t flags)
{
	if (flags & RTE_BPF_ETH_F_JIT) { // jit
		if (type == RTE_BPF_ARG_PTR) // pointer to data buffer
			return bpf_rx_callback_jit; 
		else if (type == RTE_BPF_ARG_PTR_MBUF) // pointer to rte_mbuf
			return bpf_rx_callback_mb_jit;
	} else if (type == RTE_BPF_ARG_PTR) // point to data buffer
		return bpf_rx_callback_vm;
	else if (type == RTE_BPF_ARG_PTR_MBUF) // pointer to rte_mbuf
		return bpf_rx_callback_mb_vm;

	return NULL;
}

static rte_tx_callback_fn
select_tx_callback(enum rte_bpf_arg_type type, uint32_t flags)
{
	if (flags & RTE_BPF_ETH_F_JIT) {
		if (type == RTE_BPF_ARG_PTR)
			return bpf_tx_callback_jit;
		else if (type == RTE_BPF_ARG_PTR_MBUF)
			return bpf_tx_callback_mb_jit;
	} else if (type == RTE_BPF_ARG_PTR)
		return bpf_tx_callback_vm;
	else if (type == RTE_BPF_ARG_PTR_MBUF)
		return bpf_tx_callback_mb_vm;

	return NULL;
}

/*
 * helper function to perform BPF unload for given port/queue.
 * have to introduce extra complexity (and possible slowdown) here,
 * as right now there is no safe generic way to remove RX/TX callback
 * while IO is active.
 * Still don't free memory allocated for callback handle itself,
 * again right now there is no safe way to do that without stopping RX/TX
 * on given port/queue first.
 */
static void
bpf_eth_cbi_unload(struct bpf_eth_cbi *bc)
{
	/* mark this cbi as empty */
	bc->cb = NULL;
	rte_smp_mb();

	/* make sure datapath doesn't use bpf anymore, then destroy bpf */
	bpf_eth_cbi_wait(bc);
	rte_bpf_destroy(bc->bpf);
	bpf_eth_cbi_cleanup(bc);
}

static void
bpf_eth_unload(struct bpf_eth_cbh *cbh, uint16_t port, uint16_t queue)
{
	struct bpf_eth_cbi *bc;

	bc = bpf_eth_cbh_find(cbh, port, queue);
	if (bc == NULL || bc->cb == NULL)
		return;

	if (cbh->type == BPF_ETH_RX)
		rte_eth_remove_rx_callback(port, queue, bc->cb);
	else
		rte_eth_remove_tx_callback(port, queue, bc->cb);

	bpf_eth_cbi_unload(bc);
}


void
rte_bpf_eth_rx_unload(uint16_t port, uint16_t queue)
{
	struct bpf_eth_cbh *cbh;

	cbh = &rx_cbh;
	rte_spinlock_lock(&cbh->lock);
	bpf_eth_unload(cbh, port, queue);
	rte_spinlock_unlock(&cbh->lock);
}

void
rte_bpf_eth_tx_unload(uint16_t port, uint16_t queue)
{
	struct bpf_eth_cbh *cbh;

	cbh = &tx_cbh;
	rte_spinlock_lock(&cbh->lock);
	bpf_eth_unload(cbh, port, queue);
	rte_spinlock_unlock(&cbh->lock);
}

static int
bpf_eth_elf_load(struct bpf_eth_cbh *cbh, uint16_t port, uint16_t queue,
	const struct rte_bpf_prm *prm, const char *fname, const char *sname,
	uint32_t flags)
{
	int32_t rc; // 返回值
	struct bpf_eth_cbi *bc; // information about installed BPF rx/tx callback
	struct rte_bpf *bpf; // bpf struct
	rte_rx_callback_fn frx; // rx callback function的指针？
	rte_tx_callback_fn ftx; // tx callback function
	struct rte_bpf_jit jit; // jit struct

	frx = NULL;
	ftx = NULL;

	if (prm == NULL || rte_eth_dev_is_valid_port(port) == 0 ||
			queue >= RTE_MAX_QUEUES_PER_PORT)
		return -EINVAL; // linux errno.h 22 invalid argument

	if (cbh->type == BPF_ETH_RX) // installed BPF rx callback
		frx = select_rx_callback(prm->prog_arg.type, flags); //  jit/mb_jit/vm/mb_vm 
	else
		ftx = select_tx_callback(prm->prog_arg.type, flags);

	if (frx == NULL && ftx == NULL) {
		RTE_BPF_LOG(ERR, "%s(%u, %u): no callback selected;\n",
			__func__, port, queue);
		return -EINVAL;
	}

	// create a new eBPF execution context and load given BPF code into it.
	// returns BPF handle that is used in future BPF operations, or NULL or error in rte_errno
	bpf = rte_bpf_elf_load(prm, fname, sname); // rte_bpf.h 
	if (bpf == NULL)
		return -rte_errno;

	// provide information about natively compiled code for given BPF handle.
	/*
		参数：
			bpf —— handle for the BPF code
			jit —— pointer to the rte_bpf_jit structure to be filled with related data
		
		returns：
			-EINVAL if the parameter are invalid
			Zero if operation completely successfully
	*/
	rte_bpf_get_jit(bpf, &jit); // rte_bpf.h

	if ((flags & RTE_BPF_ETH_F_JIT) != 0 && jit.func == NULL) {
		RTE_BPF_LOG(ERR, "%s(%u, %u): no JIT generated;\n",
			__func__, port, queue);
		rte_bpf_destroy(bpf);
		return -ENOTSUP;
	}

	/* setup/update global callback info  return bpf_eth_cbi*  */ 

	/*
		// information about installed BPF rx/tx callback
		struct bpf_eth_cbi{
			// used by both date & control path
			uint32_t use; // usage counter
			const struct rte_eth_rxtx_callback *cb; // callback handle
			struct rte_bpf *bpf; // BPF handle that is used in future BPF operations
			struct rte_bpf_jit jit; // Information about compiled into native ISA eBPF code.
			// used by control path only
			LIST_ENTRY(bpf_eth_cbi) link;
			uint16_t port;
			uint16_t queue;
		} __rte_cache_aligned;
	*/
	bc = bpf_eth_cbh_add(cbh, port, queue);
	if (bc == NULL)
		return -ENOMEM;

	/* remove old one, if any */
	if (bc->cb != NULL)
		bpf_eth_unload(cbh, port, queue);

	bc->bpf = bpf; // rte_bpf* 
	bc->jit = jit; // rte_bpf_jit

	if (cbh->type == BPF_ETH_RX){
		// callback handle 
		/* 
			rte_eth_add_rx_callback rte_ethdev.h中定义，在rte_ethdev.c中实现
			return NULL or error.
			On success, a pointer value which can later be used to remove the callback.
			frx —— 回调函数的函数指针

		*/
		bc->cb = rte_eth_add_rx_callback(port, queue, frx, bc); 
	}
		
		
	else
		bc->cb = rte_eth_add_tx_callback(port, queue, ftx, bc);

	if (bc->cb == NULL) {
		rc = -rte_errno;
		rte_bpf_destroy(bpf);
		bpf_eth_cbi_cleanup(bc);
	} else{
		rc = 0;
	}
		
	return rc;
}

////////////////////////////////////////////////////////////////////////
// 3. 
static int
bpf_eth_elf_load_test(struct bpf_eth_cbh *cbh, uint16_t port, uint16_t queue,
        const struct rte_bpf_prm *prm, const char *fname, const char *sname,
        uint32_t flags)
{
    int32_t rc; // 返回值
    struct bpf_eth_cbi *bc; // information about installed BPF rx/tx callback
    struct rte_bpf *bpf; // bpf struct
    rte_rx_callback_fn frx; // pointer to rx callback function
    struct rte_bpf_jit jit; // jit struct
    
    frx = NULL;

    if(prm == NULL || rte_eth_dev_is_valid_port(port) == 0 ||
        queue >= RTE_MAX_QUEUES_PER_PORT)
        return -EINVAL;
    
    // flags & RTE_BPF_ETH_F_JIT 
    // rte_bpf_arg_type type == RTE_BPF_ARG_PTR pointer to data buffer
    frx = bpf_rx_callback_jit_test; 

    if(frx == NULL){
        RTE_BPF_LOG(ERR, "%s(%u, %u): no callback selected;\n",
        __func__, port, queue);
        return -EINVAL;
    }

    // create a new eBPF execution context and load BPF code into it
    bpf = rte_bpf_elf_load(prm, fname, sname); // rye_bpf.h
    if(bpf == NULL)
        return -rte_errno;
    
    // provide information about natively compiled code for given BPF handle
    rte_bpf_get_jit(bpf, &jit); // rte_bpf.h

    if((flags & RTE_BPF_ETH_F_JIT) != 0 && jit.func == NULL){
        RTE_BPF_LOG(ERR, "%s(%u, %u): no JIT generated;\n",
            __func__, port, queue);
        rte_bpf_destroy(bpf);
        return -ENOTSUP;
    }

    // setup/update global callback info 
    // return bpf_eth_cbi*
    bc = bpf_eth_cbh_add(cbh, port, queue);
    if(bc == NULL)
        return -ENOMEN;
    
    if(bc->cb != NULL)
        bpf_eth_unload(cbh, port, queue);
    
    bc->bpf = bpf; // rte_bpf *
    bc->jit = jit; // rte_bpf_jit

    //if(cbh->type == BPF_ETH_RX)
    bc->cb = rte_eth_add_rx_callback(port, queue, frx, bc);

    if(bc->cb == NULL){
        rc = -rte_errno;
        rte_bpf_destroy(bpf);
        bpf_eth_cbi_cleanup(bc);
    } else{
        rc = 0;
    }

    return rc;
}

////////////////////////////////////////////////////////////////////////
int
rte_bpf_eth_rx_elf_load(uint16_t port, uint16_t queue,
	const struct rte_bpf_prm *prm, const char *fname, const char *sname,
	uint32_t flags)
{
	int32_t rc;
	struct bpf_eth_cbh *cbh;

	cbh = &rx_cbh;
	rte_spinlock_lock(&cbh->lock);
	rc = bpf_eth_elf_load(cbh, port, queue, prm, fname, sname, flags);
	rte_spinlock_unlock(&cbh->lock);

	return rc;
}

/////////////////////////////////////////////////////////////////
// 4.
int
rte_bpf_eth_rx_elf_load_test(uint16_t port, uint16_t queue,
    const struct rte_bpf_prm *prm, const char *fname, const char *sname,
     uint32_t flags)
{
        int32_t rc;
        struct bpf_eth_cbh *cbh;

        cbh = &rx_cbh;
        rte_spinlock_lock(&cbh->lock);
        rc = bpf_eth_elf_load_test(cbh, port, queue, prm, fname, sname, flags);
        rte_spinlock_unlock(&cbh->lock);

        return rc;
}
//////////////////////////////////////////////////////////////////////
int
rte_bpf_eth_tx_elf_load(uint16_t port, uint16_t queue,
	const struct rte_bpf_prm *prm, const char *fname, const char *sname,
	uint32_t flags)
{
	int32_t rc;
	struct bpf_eth_cbh *cbh;

	cbh = &tx_cbh;
	rte_spinlock_lock(&cbh->lock);
	rc = bpf_eth_elf_load(cbh, port, queue, prm, fname, sname, flags);
	rte_spinlock_unlock(&cbh->lock);

	return rc;
}
