import asyncio
from adkg.polynomial import polynomials_over
from pypairing import G1 as blsG1, blsmultiexp
from pypairing import curve25519multiexp

class BRMsgType:
    R1 = 1
    R2 = 2

async def batch_reconstruct(sending, receivers, my_id, t, degree, g, output, ZR, G1, send, recv, shares=None, comms=None):
    poly = polynomials_over(ZR)
    my_exponents = [ZR(1), ZR(my_id+1)]
    #degree+1 secrets will be recovered in each batch
    for _ in range(degree-1):
        my_exponents.append(my_exponents[-1] * ZR(my_id+1))
        
    if G1 is blsG1:
        multiexp = blsmultiexp
    else:
        multiexp = curve25519multiexp

    if sending:
        assert shares is not None
        def chunks(lst, n):
            """Yield successive n-sized chunks from lst."""
            for i in range(0, len(lst), n):
                yield lst[i:i + n]
        share_groups = chunks(shares, degree+1)
        evals = []
        for share_group in share_groups:
            f = poly(share_group)
            evals.append([f(id + 1) for id in receivers])
        for i, id in enumerate(receivers):
            send(id, (BRMsgType.R1, [eval[i] for eval in evals]))
    
    if my_id in receivers:
        r1_set = set()
        r2_set = set()
        r1_sharess = {}
        r2_sharess = {}
        if degree > t:
            assert comms is not None

        while True:
            sender, msg = await recv()
            if msg[0] == BRMsgType.R1:
                #check message validity
                if sender in r1_set:
                    continue
                if degree > t:
                    valid = True
                    for i, share in enumerate(msg[1]):
                        #assume comms is [ [all s1 comms], [all s2 comms], ...]
                        remaining_comms = len(comms) - i*(degree+1)
                        test_comms = [comms[i*(degree+1) + j][sender+1] for j in range(min(degree+1, remaining_comms))]
                        if g ** share != multiexp(test_comms, my_exponents):
                            valid = False
                            print("ABORT! ABORT!")
                            break
                    if not valid:
                        continue

                for i, share in enumerate(msg[1]):    
                    r1_sharess[i] = r1_sharess.get(i, []) + [ (sender+1, msg[1][i]) ]
                r1_set.add(sender)
                #todo: robust for degree t
                if len(r1_set) == degree+1:
                    evals = [ poly.interpolate_at(r1_shares, 0) for r1_shares in r1_sharess.values()]
                    for i, id in enumerate(receivers):
                        send(id, (BRMsgType.R2, evals))
            
            if msg[0] == BRMsgType.R2:
                if sender in r2_set:
                    continue
                if degree > t:
                    valid = True
                    sender_exponents = [ZR(1), ZR(sender+1)]
                    for _ in range(degree-1):
                        sender_exponents.append(sender_exponents[-1] * ZR(sender+1))
                    for i, share in enumerate(msg[1]):
                        #assume comms is [ [all s1 comms], [all s2 comms], ...]
                        remaining_comms = len(comms) - i*(degree+1)
                        test_comms_r2 = [comms[i*(degree+1) + j][0] for j in range(min(degree+1, remaining_comms))]
                        if g ** share != multiexp(test_comms_r2, sender_exponents):
                            valid = False
                            print("ABORT! ABORT!")
                            break
                    if not valid:
                        continue

                for i, share in enumerate(msg[1]):
                    r2_sharess[i] = r2_sharess.get(i, []) + [ (sender+1, msg[1][i]) ]
                r2_set.add(sender)
                #todo: robust
                if len(r2_set) == degree+1:
                    outs = []
                    for r2_shares in r2_sharess.values():
                        r2 = poly.interpolate(r2_shares)
                        outs += r2.coeffs
                    output(outs)
                    break
                    
            

    