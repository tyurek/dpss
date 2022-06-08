from benchmark.test_benchmark_rbc import rbc
from adkg.broadcast.optqrbc import optqrbc as qrbc
#from adkg.broadcast.qrbc import qrbc
from random import randint
from pytest import mark
from asyncio import create_task, gather
from asyncio import Queue, Event
import os

@mark.asyncio
async def test_rbc(test_router):
    n, t = 4, 1
    msglen = 10*(t+1)
    sends, recvs, _ = test_router(2*n)
    dealer_id = randint(0, n-1)
    dealer_id = randint(1, n)
    msg = os.urandom(msglen)

    sid = "sidA"

    async def predicate(m=None):
        return True 

    rbc_tasks = [None]*n
    ids = list(range(1,n+1))
    outputs = [Queue() for i in range(n)]
    
    for i in range(n):
        rbc_tasks[i] = create_task(
            qrbc(
                sid, 
                ids[i], 
                ids, 
                t, 
                dealer_id, 
                predicate,
                msg,
                outputs[i].put_nowait,
                sends[ids[i]], 
                recvs[ids[i]],
            )
        )

    outs = await gather(*[output.get() for output in outputs])
    assert len(set(outs)) == 1
    for task in rbc_tasks:
        task.cancel()

@mark.asyncio
async def test_rbc_external_leader(test_router):
    n, t = 4, 1
    msglen = 10*(t+1)
    sends, recvs, _ = test_router(2*n)
    msg = os.urandom(msglen)

    sid = "sidA"

    async def predicate(m=None):
        return True 

    rbc_tasks = [None]*n
    ids = list(range(1,n+1))
    dealer_id = n+3
    outputs = [Queue() for i in range(n)]
    
    for i in range(n):
        rbc_tasks[i] = create_task(
            qrbc(
                sid, 
                ids[i], 
                ids, 
                t, 
                dealer_id, 
                predicate,
                msg,
                outputs[i].put_nowait,
                sends[ids[i]], 
                recvs[ids[i]],
            )
        )
    create_task(qrbc(sid, dealer_id, ids, t, dealer_id, predicate, msg, None, sends[dealer_id], recvs[dealer_id]))

    outs = await gather(*[output.get() for output in outputs])
    assert len(set(outs)) == 1
    for task in rbc_tasks:
        task.cancel()

