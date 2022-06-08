import logging
from pytest import mark
from random import randint
from adkg.polynomial import polynomials_over
from adkg.dpss_ped_batch import DPSS_PED_BATCH
from adkg.utils.misc import print_exception_callback
import asyncio
import phe
from pickle import dumps


def get_avss_params(ids):
    #from pypairing import G1, ZR
    from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    g = G1.rand()
    h = G1.rand()
    n = len(ids)
    keypairs = [phe.paillier.generate_paillier_keypair() for _ in range(n)]
    public_keys = {ids[i]:keypairs[i][0] for i in range(n)}
    private_keys = [keypairs[i][1] for i in range(n)]
    private_keys_dict = {ids[i]:private_keys[i] for i in range(n)}
    #public_keys, private_keys = [[keypairs[i][j] for i in range(n)] for j in range(2)]
    return g, h, public_keys, private_keys_dict


@mark.parametrize("t", [1,3,6])
def test_benchmark_dpss_t_faults(benchmark_router, benchmark, t):
    #from pypairing import G1, ZR
    from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    n = 3 * t + 1
    d = n-t-1
    t_prime = t
    n_prime = n
    d_prime = d
    old_committee, new_committee = {}, {}
    old_committee['ids'], old_committee['t'], old_committee['degree'] = list(range(n)), t, d
    new_committee['ids'], new_committee['t'], new_committee['degree'] = list(range(n, n+n_prime)), t_prime, d_prime
    ids = old_committee['ids'] + new_committee['ids']

    g, h, pks, sks = get_avss_params(old_committee['ids'] + new_committee['ids'])
    sends, recvs, _ = benchmark_router(len(old_committee['ids'] + new_committee['ids']))
    batchsize = 3*(t+1)

    secrets, secrets_hat = [ZR.random() for b in range(batchsize)], [ZR.random() for b in range(batchsize)]
    poly = polynomials_over(ZR)
    polys = [poly.random(d, secret) for secret in secrets]
    polys_hat = [poly.random(d, secret) for secret in secrets_hat]
    shares = [ [phi(id+1) for phi in polys] for id in old_committee['ids'] ]
    shares_hat = [ [phi(id+1) for phi in polys_hat] for id in old_committee['ids'] ]
    #comms = [ [g**(phi(0)) * h**(phi_hat(0))] + [g**(phi(id+1)) * h**(phi_hat(id+1)) for id in old_committee['ids']] for phi, phi_hat in zip(polys, polys_hat)]
    comms = [ [g**phi(id+1) * h ** phi_hat(id+1) for id in [-1] + old_committee['ids']] for phi, phi_hat in zip(polys, polys_hat) ]

    ids = old_committee['ids'][:-t] + new_committee['ids'][:-t_prime]

    hbavss_list = []
    dpss_tasks = [None] * len(ids)
    
    loop = asyncio.get_event_loop()
    
    def _prog():
        loop.run_until_complete(to_benchmark())

    async def to_benchmark():
        sends, recvs, _ = benchmark_router(len(old_committee['ids'] + new_committee['ids']))
        hbavss_list = []
        dpss_tasks = [None] * len(ids)
        for i in range(len(ids)):
            dpss = DPSS_PED_BATCH(pks, sks[ids[i]], g, h, old_committee, new_committee, ids[i], G1, ZR, sends[ids[i]], recvs[ids[i]])
            if ids[i] in old_committee['ids']:
                dpss_tasks[i] = asyncio.create_task(dpss.dpss(0, values=(shares[i],shares_hat[i]), comms=comms))
            else:
                hbavss_list.append(dpss)
                dpss_tasks[i] = asyncio.create_task(dpss.dpss(0))
            dpss_tasks[i].add_done_callback(print_exception_callback)

        outputs = await asyncio.gather(
            #*[hbavss_list[id].output_queue.get() for id in new_committee['ids']]
            *[entry.output_queue.get() for entry in hbavss_list]
        )
    
    benchmark(_prog)

@mark.parametrize("t", [1,3,6])
def test_benchmark_dpss(benchmark_router, benchmark, t):
    #from pypairing import G1, ZR
    from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    n = 3 * t + 1
    d = n-t-1
    t_prime = t
    n_prime = n
    d_prime = d
    old_committee, new_committee = {}, {}
    old_committee['ids'], old_committee['t'], old_committee['degree'] = list(range(n)), t, d
    new_committee['ids'], new_committee['t'], new_committee['degree'] = list(range(n, n+n_prime)), t_prime, d_prime
    ids = old_committee['ids'] + new_committee['ids']

    g, h, pks, sks = get_avss_params(old_committee['ids'] + new_committee['ids'])
    sends, recvs, _ = benchmark_router(len(old_committee['ids'] + new_committee['ids']))
    batchsize = 3*(t+1)

    secrets, secrets_hat = [ZR.random() for b in range(batchsize)], [ZR.random() for b in range(batchsize)]
    poly = polynomials_over(ZR)
    polys = [poly.random(d, secret) for secret in secrets]
    polys_hat = [poly.random(d, secret) for secret in secrets_hat]
    shares = [ [phi(id+1) for phi in polys] for id in old_committee['ids'] ]
    shares_hat = [ [phi(id+1) for phi in polys_hat] for id in old_committee['ids'] ]
    #comms = [ [g**(phi(0)) * h**(phi_hat(0))] + [g**(phi(id+1)) * h**(phi_hat(id+1)) for id in old_committee['ids']] for phi, phi_hat in zip(polys, polys_hat)]
    comms = [ [g**phi(id+1) * h ** phi_hat(id+1) for id in [-1] + old_committee['ids']] for phi, phi_hat in zip(polys, polys_hat) ]

    hbavss_list = []
    dpss_tasks = [None] * len(ids)
    
    loop = asyncio.get_event_loop()
    
    def _prog():
        loop.run_until_complete(to_benchmark())

    async def to_benchmark():
        sends, recvs, _ = benchmark_router(len(old_committee['ids'] + new_committee['ids']))
        hbavss_list = []
        dpss_tasks = [None] * len(ids)
        for i in range(len(ids)):
            dpss = DPSS_PED_BATCH(pks, sks[ids[i]], g, h, old_committee, new_committee, ids[i], G1, ZR, sends[ids[i]], recvs[ids[i]])
            if ids[i] in old_committee['ids']:
                dpss_tasks[i] = asyncio.create_task(dpss.dpss(0, values=(shares[i],shares_hat[i]), comms=comms))
            else:
                hbavss_list.append(dpss)
                dpss_tasks[i] = asyncio.create_task(dpss.dpss(0))
            dpss_tasks[i].add_done_callback(print_exception_callback)

        outputs = await asyncio.gather(
            #*[hbavss_list[id].output_queue.get() for id in new_committee['ids']]
            *[entry.output_queue.get() for entry in hbavss_list]
        )
    benchmark(_prog)