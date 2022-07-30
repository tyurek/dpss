import logging
from pytest import mark
from random import randint
from dpss.polynomial import polynomials_over
from dpss.dpss import DPSS
from dpss.utils.misc import print_exception_callback
import asyncio
import phe


def get_avss_params(ids):
    from pypairing import G1, ZR
    # from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    g = G1.rand()
    n = len(ids)
    keypairs = [phe.paillier.generate_paillier_keypair() for _ in range(n)]
    public_keys = {ids[i]:keypairs[i][0] for i in range(n)}
    private_keys = [keypairs[i][1] for i in range(n)]
    #public_keys, private_keys = [[keypairs[i][j] for i in range(n)] for j in range(2)]
    return g, public_keys, private_keys


@mark.asyncio
async def test_dpss(test_router):
    from pypairing import G1, ZR
    # from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    t = 1
    n = 3 * t + 1
    d = t + 1
    t_prime = t
    n_prime = n
    d_prime = d
    old_committee, new_committee = {}, {}
    old_committee['ids'], old_committee['t'], old_committee['degree'] = list(range(n)), t, d
    new_committee['ids'], new_committee['t'], new_committee['degree'] = list(range(n, n+n_prime)), t_prime, d_prime
    ids = old_committee['ids'] + new_committee['ids']

    g, pks, sks = get_avss_params(old_committee['ids'] + new_committee['ids'])
    sends, recvs, _ = test_router(len(old_committee['ids'] + new_committee['ids']), maxdelay = 0.1, seed = 2)

    secret = ZR.random()
    poly = polynomials_over(ZR)
    phi = poly.random(d, secret)
    shares = [phi(id+1) for id in old_committee['ids']]
    comms = [g**(phi(0))] + [g**(phi(id+1)) for id in old_committee['ids']]
    dpss_tasks = [None] * n

    hbavss_list = [None] * len(ids)
    dpss_tasks = [None] * len(ids)
    for i in range(len(ids)):
        dpss = DPSS(pks, sks[i], g, old_committee, new_committee, ids[i], G1, ZR, sends[ids[i]], recvs[ids[i]])
        hbavss_list[i] = dpss
        if ids[i] in old_committee['ids']:
            dpss_tasks[i] = asyncio.create_task(dpss.dpss(0, share=shares[i], comms=comms))
        else:
            dpss_tasks[i] = asyncio.create_task(dpss.dpss(0))
        dpss_tasks[i].add_done_callback(print_exception_callback)

    outputs = await asyncio.gather(
        *[hbavss_list[id].output_queue.get() for id in new_committee['ids']]
    )
    shares = [output[1] for output in outputs]
    for task in dpss_tasks:
        task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            #polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
            polynomials_over(ZR).interpolate_at(zip((id+1 for id in new_committee['ids']), item))
        )

    assert recovered_values == [secret]
    
    print(shares)
    print([g ** share[0] for share in shares])
    print(outputs[0][2])