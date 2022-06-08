import logging
from pytest import mark
from random import randint
from adkg.polynomial import polynomials_over
from adkg.acss_dcr2 import ACSS_DCR
from adkg.utils.misc import print_exception_callback
import asyncio
import phe


def get_avss_params(ids, t):
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
async def test_acss_dcr(test_router):
    from pypairing import G1, ZR
    # from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    t = 1
    n = 3 * t + 1
    d = t
    ids = list(range(1,n+1))
    ids[-1] += 2

    g, pks, sks = get_avss_params(ids, t)
    sends, recvs, _ = test_router(2*n)

    secret = ZR.random()
    avss_tasks = [None] * n
    dealer_id = ids[randint(0, n - 1)]

    shares = [None] * n
    hbavss_list = [None] * n
    for i in range(n):
        hbavss = ACSS_DCR(pks, sks[i], g, ids, t, d, ids[i], G1, ZR, sends[ids[i]], recvs[ids[i]])
        hbavss_list[i] = hbavss
        if ids[i] == dealer_id:
            avss_tasks[i] = asyncio.create_task(hbavss.avss(0, values=[secret]))
        else:
            avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
        avss_tasks[i].add_done_callback(print_exception_callback)
    outputs = await asyncio.gather(
        *[hbavss_list[i].output_queue.get() for i in range(n)]
    )
    shares = [output[2] for output in outputs]
    for task in avss_tasks:
        task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            #polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
            polynomials_over(ZR).interpolate_at(zip((id+1 for id in ids), item))
        )

    assert recovered_values == [secret]

@mark.asyncio
async def test_acss_dcr_external_dealer(test_router):
    from pypairing import G1, ZR
    # from pypairing import Curve25519ZR as ZR, Curve25519G as G1
    t = 1
    n = 3 * t + 1
    d = t
    ids = list(range(1,n+1))
    ids[-1] += 2

    g, pks, sks = get_avss_params(ids, t)
    sends, recvs, _ = test_router(2*n)

    secret = ZR.random()
    avss_tasks = [None] * n
    dealer_id = n+3

    shares = [None] * n
    hbavss_list = [None] * n
    for i in range(n):
        hbavss = ACSS_DCR(pks, sks[i], g, ids, t, d, ids[i], G1, ZR, sends[ids[i]], recvs[ids[i]])
        hbavss_list[i] = hbavss
        avss_tasks[i] = asyncio.create_task(hbavss.avss(0, dealer_id=dealer_id))
        avss_tasks[i].add_done_callback(print_exception_callback)
    
    dealeracss = ACSS_DCR(pks, sks[i], g, ids, t, d, dealer_id, G1, ZR, sends[dealer_id], recvs[dealer_id])
    dealertask = asyncio.create_task(dealeracss.avss(0, values=[secret]))
    
    outputs = await asyncio.gather(
        *[hbavss_list[i].output_queue.get() for i in range(n)]
    )
    shares = [output[2] for output in outputs]
    for task in avss_tasks + [dealertask]:
        task.cancel()

    fliped_shares = list(map(list, zip(*shares)))
    recovered_values = []
    for item in fliped_shares:
        recovered_values.append(
            #polynomials_over(ZR).interpolate_at(zip(range(1, n + 1), item))
            polynomials_over(ZR).interpolate_at(zip((id+1 for id in ids), item))
        )

    assert recovered_values == [secret]