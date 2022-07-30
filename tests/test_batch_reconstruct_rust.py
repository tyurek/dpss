import logging
from pytest import mark
from random import randint
from dpss.polynomial import polynomials_over
from dpss.batch_reconstruct_rust import batch_reconstruct
from dpss.utils.misc import print_exception_callback
import asyncio


@mark.asyncio
async def test_br(test_router):
    #from pypairing import G1, ZR
    from pypairing import Curve25519ZR as ZR, Curve25519G as G1
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

    sends, recvs, _ = test_router(len(old_committee['ids'] + new_committee['ids']), maxdelay = 0.1)
    
    secrets = [ZR.random() for _ in range(2*d+3)]
    poly = polynomials_over(ZR)
    polys = [poly.random(d, secret) for secret in secrets]
    shares = [ [phi(id+1) for phi in polys] for id in old_committee['ids'] ]
    
    g = G1.rand()
    comms = [ [g**phi(id+1) for id in [-1] + old_committee['ids']] for phi in polys ]

    output_queues = [asyncio.Queue() for id in new_committee['ids']]

    for i, id in enumerate(old_committee['ids']):
        task = asyncio.create_task(batch_reconstruct(True, new_committee['ids'], id, t, d, g, None, ZR, G1, sends[id], recvs[id], shares=shares[i]))
        task.add_done_callback(print_exception_callback)
    
    for i, id in enumerate(new_committee['ids']):
        task = asyncio.create_task(batch_reconstruct(False, new_committee['ids'], id, t, d, g, output_queues[i].put_nowait, ZR, G1, sends[id], recvs[id], comms=comms))
        task.add_done_callback(print_exception_callback)
    
    outputs = await asyncio.gather(
        *[output_queues[i].get() for i in range(len(new_committee['ids']))]
    )
    assert outputs[1] == secrets