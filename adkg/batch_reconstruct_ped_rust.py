import asyncio
from adkg.polynomial import polynomials_over
from pypairing import G1 as blsG1, blsmultiexp
from pypairing import curve25519multiexp

class BRMsgType:
    R1 = 1
    R2 = 2

async def batch_reconstruct_ped(sending, receivers, my_id, t, degree, g, h, output, ZR, G1, send, recv, shares=None, shares_hat=None, comms=None):
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
        assert shares_hat is not None
        def chunks(lst, n):
            """Yield successive n-sized chunks from lst."""
            for i in range(0, len(lst), n):
                yield lst[i:i + n]
        share_groups, share_hat_groups = chunks(shares, degree+1), chunks(shares_hat, degree+1)
        evals = []
        for share_group, share_hat_group in zip(share_groups, share_hat_groups):
            f, f_hat = poly(share_group), poly(share_hat_group)
            evals.append([[f(id + 1), f_hat(id + 1)] for id in receivers])
        for i, id in enumerate(receivers):
            send(id, (BRMsgType.R1, [eval[i] for eval in evals]))
    
    if my_id in receivers:
        r1_set = set()
        r2_set = set()
        r1_sharess = {}
        r1_sharess_hat = {}
        r2_sharess = {}
        r2_sharess_hat = {}
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
                    for i, [share, share_hat] in enumerate(msg[1]):
                        #assume comms is [ [all s1 comms], [all s2 comms], ...]
                        remaining_comms = len(comms) - i*(degree+1)
                        test_comms = [comms[i*(degree+1) + j][sender+1] for j in range(min(degree+1, remaining_comms))]
                        if g ** share * h ** share_hat != multiexp(test_comms, my_exponents):
                            valid = False
                            print("ABORT! ABORT!")
                            break
                    if not valid:
                        continue

                for i, [share, share_hat] in enumerate(msg[1]):
                    #a one-line way of saying, if the list exists, append. If not, create it first then append
                    r1_sharess[i] = r1_sharess.get(i, []) + [ (sender+1, share) ]
                    r1_sharess_hat[i] = r1_sharess_hat.get(i, []) + [ (sender+1, share_hat) ]
                r1_set.add(sender)
                #todo: robust for degree t
                if len(r1_set) == degree+1:
                    evals = [ poly.interpolate_at(r1_shares, 0) for r1_shares in r1_sharess.values()]
                    evals_hat = [ poly.interpolate_at(r1_shares_hat, 0) for r1_shares_hat in r1_sharess_hat.values()]
                    for i, id in enumerate(receivers):
                        send(id, (BRMsgType.R2, list(zip(evals, evals_hat))))
            
            if msg[0] == BRMsgType.R2:
                if sender in r2_set:
                    continue
                if degree > t:
                    valid = True
                    sender_exponents = [ZR(1), ZR(sender+1)]
                    for _ in range(degree-1):
                        sender_exponents.append(sender_exponents[-1] * ZR(sender+1))
                    for i, [share, share_hat] in enumerate(msg[1]):
                        remaining_comms = len(comms) - i*(degree+1)
                        test_comms_r2 = [comms[i*(degree+1) + j][0] for j in range(min(degree+1, remaining_comms))]
                        if g ** share * h ** share_hat != multiexp(test_comms_r2, sender_exponents):
                            valid = False
                            print("ABORT! ABORT! (but in R2)")
                            break
                    if not valid:
                        continue

                for i, [share, share_hat] in enumerate(msg[1]):
                    r2_sharess[i] = r2_sharess.get(i, []) + [ (sender+1, share) ]
                    r2_sharess_hat[i] = r2_sharess_hat.get(i, []) + [ (sender+1, share_hat) ]
                r2_set.add(sender)
                #todo: robust
                if len(r2_set) == degree+1:
                    outsecrets, outsecrets_hat = [], []
                    for r2_shares in r2_sharess.values():
                        r2 = poly.interpolate(r2_shares)
                        outsecrets += r2.coeffs
                    for r2_shares_hat in r2_sharess_hat.values():
                        r2 = poly.interpolate(r2_shares_hat)
                        outsecrets_hat += r2.coeffs
                    output([outsecrets, outsecrets_hat])
                    break
                    
            

    