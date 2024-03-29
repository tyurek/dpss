import random
from asyncio import Queue, Event
from asyncio import get_event_loop, create_task, gather
from pytest import mark
from functools import partial

from dpss.broadcast.commoncoin import shared_coin
from dpss.broadcast.tylerba_beacon import tylerba
from dpss.broadcast.crypto.boldyreva import dealer
from dpss.random_beacon import RandomBeacon
from collections import defaultdict
from dpss.utils.misc import print_exception_callback


def byzantine_broadcast_router(n, maxdelay=0.005, seed=None, **byzargs):
    """Builds a set of connected channels, with random delay.

    :return: (receives, sends) endpoints.
    """
    rnd = random.Random(seed)
    queues = [Queue() for _ in range(n)]

    def make_broadcast(i):
        def _send(j, o):
            delay = rnd.random() * maxdelay
            if j == byzargs.get("byznode"):
                try:
                    byz_tag = byzargs["byz_message_type"]
                except KeyError:
                    pass
                else:
                    o = list(o)
                    o[0] = byz_tag
                    o = tuple(o)
            get_event_loop().call_later(delay, queues[j].put_nowait, (i, o))

            if j == byzargs.get("byznode") and o[0] == byzargs.get(
                "redundant_msg_type"
            ):
                get_event_loop().call_later(delay, queues[j].put_nowait, (i, o))

        def _bc(o):
            for j in range(n):
                _send(j, o)

        return _bc
    
    def make_recv(j):
        async def _recv():
            # print('RECV %2d' % (j))
            (i, o) = await queues[j].get()
            return (i, o)

        return _recv

    return ([make_broadcast(i) for i in range(n)], [make_recv(j) for j in range(n)])


def release_held_messages(q, receivers):
    for m in q:
        receivers[m["receiver"]].put((m["sender"], m["msg"]))


def dummy_coin(sid, n, f):
    counter = defaultdict(int)
    events = defaultdict(Event)

    async def get_coin(round):
        # Return a pseudorandom number depending on the round, without blocking
        counter[round] += 1
        if counter[round] == f+1:
            events[round].set()
        await events[round].wait()
        return hash((sid, round)) % 2
    
    return get_coin


async def _make_coins(test_router, sid, n, f, seed):
    # Generate keys
    pk, sks = dealer(n, f + 1)
    _, recvs, sends = test_router(n, seed=seed)
    result = await gather(
        *[shared_coin(sid, i, n, f, pk, sks[i], sends[i], recvs[i]) for i in range(n)]
    )
    return zip(*result)

@mark.parametrize("seed", (1, 2))
@mark.asyncio
async def test_tylerba(seed, test_router):
    n, f = 4, 1
    # Generate keys
    sid = "sidA"
    # Test everything when runs are OK
    # if seed is not None: print 'SEED:', seed
    rnd = random.Random(seed)

    # Router
    _, recvs, sends = test_router(2*n+1, seed=seed)

    threads = []
    inputs = []
    outputs = []
    nodes = list(range(3,n+3))
    def broadcast(o):
        for i in range(2*n):
            sends[-1](i, o)

    beacon = RandomBeacon(f, broadcast, recvs[-1])
    beacon_requests = [partial(sends[i], 2*n) for i in range(2*n)]

    for i in range(n):
        inputs.append(Queue())
        outputs.append(Queue())

        t = create_task(
            tylerba(
                sid,
                nodes[i],
                nodes,
                f,
                beacon_requests[nodes[i]],
                inputs[i].get,
                outputs[i].put_nowait,
                sends[nodes[i]],
                recvs[nodes[i]],
            )
        )
        threads.append(t)
        t.add_done_callback(print_exception_callback)

    for i in range(n):
        inputs[i].put_nowait(random.randint(0, 1))

    outs = await gather(*[outputs[i].get() for i in range(n)])
    assert len(set(outs)) == 1
    await gather(*threads)
    [task.cancel() for task in recv_tasks]


@mark.parametrize("seed", (1, 2))
@mark.asyncio
async def test_tylerba_nocoin(seed, test_router):
    n, f = 4, 1
    # Generate keys
    sid = "sidA"
    # Test everything when runs are OK
    # Router
    _, recvs, sends = test_router(2*n, seed=seed)

    threads = []
    inputs = []
    outputs = []
    nodes = list(range(1,n+1))

    for i in range(n):
        inputs.append(Queue())
        outputs.append(Queue())

        t = create_task(
            tylerba(
                sid,
                nodes[i],
                nodes, 
                f, 
                None, 
                inputs[i].get,
                outputs[i].put_nowait,
                sends[nodes[i]],
                recvs[nodes[i]],
            )
        )
        threads.append(t)
    
    for i in range(n-f):
        inputs[i].put_nowait(0)
    for i in range(n-f, n):
        inputs[i].put_nowait(random.randint(0,1))

    outs = await gather(*[outputs[i].get() for i in range (n)])
    assert len(set(outs)) == 1
    [task.cancel() for task in recv_tasks]