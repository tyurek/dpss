import logging
from pytest import mark
from random import randint
from dpss.polynomial import polynomials_over
from dpss.dpss_ped_lt_batch import DPSS_PED_LT_BATCH
from dpss.utils.misc import print_exception_callback
from dpss.poly_commit_const import PolyCommitConst, gen_pc_const_crs

import asyncio
from pickle import dumps


def get_avss_params(ids):
    from pypairing import G1, ZR
    # from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    g = G1.rand()
    h = G1.rand()
    n = len(ids)
    private_keys = [ZR.rand() for i in range(n)]
    public_keys = {ids[i]:g ** private_keys[i] for i in range(n)}
    private_keys_dict = {ids[i]:private_keys[i] for i in range(n)}
    return g, h, public_keys, private_keys_dict


@mark.parametrize("t", [1,3,6,10])
def test_benchmark_dpss_lt_t_crashes(test_router, benchmark, t):
    from pypairing import G1, ZR
    n = 3 * t + 1
    d = t
    t_prime = t
    n_prime = n
    d_prime = d
    old_committee, new_committee = {}, {}
    old_committee['ids'], old_committee['t'], old_committee['degree'] = list(range(n)), t, d
    new_committee['ids'], new_committee['t'], new_committee['degree'] = list(range(n, n+n_prime)), t_prime, d_prime
    ids = old_committee['ids'] + new_committee['ids']

    g, h, pks, sks = get_avss_params(old_committee['ids'] + new_committee['ids'])
    alpha = ZR.random()
    crs = gen_pc_const_crs(t, alpha=alpha, g=g, h=h)
    pc = PolyCommitConst(crs)
    sends, recvs, _ = test_router(len(old_committee['ids'] + new_committee['ids']), maxdelay = 0)
    batchsize = 100*n

    secrets, secrets_hat = [ZR.random() for b in range(batchsize)], [ZR.random() for b in range(batchsize)]
    poly = polynomials_over(ZR)
    polys = [poly.random(d, secret) for secret in secrets]
    polys_hat = [poly.random(d, secret) for secret in secrets_hat]
    shares = [ [phi(id+1) for phi in polys] for id in old_committee['ids'] ]
    shares_hat = [ [phi(id+1) for phi in polys_hat] for id in old_committee['ids'] ]

    
    ids = old_committee['ids'][:-t] + new_committee['ids'][:-t_prime]

    hbavss_list = [None] * len(ids)
    hbavss_list = []
    dpss_tasks = [None] * len(ids)
    
    #dpss_list = [ DPSS_PED_LT_BATCH(pks, sks[ids[i]], g, h, old_committee, new_committee, ids[i], G1, ZR, sends[ids[i]], recvs[ids[i]], pc) for i in range(len(ids))]
    loop = asyncio.get_event_loop()
    
    def _prog():
        loop.run_until_complete(to_benchmark())

    async def to_benchmark():
        sends, recvs, _ = test_router(len(old_committee['ids'] + new_committee['ids']), maxdelay = 0)
        hbavss_list = []
        dpss_tasks = [None] * len(ids)
        for i in range(len(ids)):
            dpss = DPSS_PED_LT_BATCH(pks, sks[ids[i]], g, h, old_committee, new_committee, ids[i], G1, ZR, sends[ids[i]], recvs[ids[i]], pc)
            #hbavss_list[i] = dpss
            if ids[i] in old_committee['ids']:
                dpss_tasks[i] = asyncio.create_task(dpss.dpss(0, values=(shares[i],shares_hat[i])))
            else:
                hbavss_list.append(dpss)
                dpss_tasks[i] = asyncio.create_task(dpss.dpss(0))
            dpss_tasks[i].add_done_callback(print_exception_callback)

        outputs = await asyncio.gather(
            #*[hbavss_list[id].output_queue.get() for id in new_committee['ids'][:-t_prime]]
            *[entry.output_queue.get() for entry in hbavss_list]
        )
    benchmark(_prog)
    '''
    shares = [output[1] for output in outputs]
    for task in dpss_tasks:
        task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            polynomials_over(ZR).interpolate_at(zip((id+1 for id in new_committee['ids'][:-t_prime]), item))
        )

    assert recovered_values == secrets

    shares_hat = [output[2] for output in outputs]
    fliped_shares_hat = list(map(list, zip(*shares_hat)))
    recovered_values_hat = []
    for item in fliped_shares_hat:
        recovered_values_hat.append(
            #polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
            polynomials_over(ZR).interpolate_at(zip((id+1 for id in new_committee['ids'][:-t_prime]), item))
        )

    assert recovered_values_hat == secrets_hat
    '''
@mark.parametrize("t", [1,3,6,10])
def test_benchmark_dpss_lt_t(test_router, benchmark, t):
    from pypairing import G1, ZR
    n = 3 * t + 1
    d = t
    t_prime = t
    n_prime = n
    d_prime = d
    old_committee, new_committee = {}, {}
    old_committee['ids'], old_committee['t'], old_committee['degree'] = list(range(n)), t, d
    new_committee['ids'], new_committee['t'], new_committee['degree'] = list(range(n, n+n_prime)), t_prime, d_prime
    ids = old_committee['ids'] + new_committee['ids']

    g, h, pks, sks = get_avss_params(old_committee['ids'] + new_committee['ids'])
    alpha = ZR.random()
    crs = gen_pc_const_crs(t, alpha=alpha, g=g, h=h)
    pc = PolyCommitConst(crs)
    sends, recvs, _ = test_router(len(old_committee['ids'] + new_committee['ids']), maxdelay = 0)
    batchsize = 100*n

    secrets, secrets_hat = [ZR.random() for b in range(batchsize)], [ZR.random() for b in range(batchsize)]
    poly = polynomials_over(ZR)
    polys = [poly.random(d, secret) for secret in secrets]
    polys_hat = [poly.random(d, secret) for secret in secrets_hat]
    shares = [ [phi(id+1) for phi in polys] for id in old_committee['ids'] ]
    shares_hat = [ [phi(id+1) for phi in polys_hat] for id in old_committee['ids'] ]

    
    #ids = old_committee['ids'][:-t] + new_committee['ids'][:-t_prime]

    hbavss_list = [None] * len(ids)
    hbavss_list = []
    dpss_tasks = [None] * len(ids)
    
    #dpss_list = [ DPSS_PED_LT_BATCH(pks, sks[ids[i]], g, h, old_committee, new_committee, ids[i], G1, ZR, sends[ids[i]], recvs[ids[i]], pc) for i in range(len(ids))]
    loop = asyncio.get_event_loop()
    
    def _prog():
        loop.run_until_complete(to_benchmark())

    async def to_benchmark():
        sends, recvs, _ = test_router(len(old_committee['ids'] + new_committee['ids']), maxdelay = 0)
        hbavss_list = []
        dpss_tasks = [None] * len(ids)
        for i in range(len(ids)):
            dpss = DPSS_PED_LT_BATCH(pks, sks[ids[i]], g, h, old_committee, new_committee, ids[i], G1, ZR, sends[ids[i]], recvs[ids[i]], pc)
            #hbavss_list[i] = dpss
            if ids[i] in old_committee['ids']:
                dpss_tasks[i] = asyncio.create_task(dpss.dpss(0, values=(shares[i],shares_hat[i])))
            else:
                hbavss_list.append(dpss)
                dpss_tasks[i] = asyncio.create_task(dpss.dpss(0))
            dpss_tasks[i].add_done_callback(print_exception_callback)

        outputs = await asyncio.gather(
            #*[hbavss_list[id].output_queue.get() for id in new_committee['ids'][:-t_prime]]
            *[entry.output_queue.get() for entry in hbavss_list]
        )
    benchmark(_prog)


#if __name__ == "__main__":
