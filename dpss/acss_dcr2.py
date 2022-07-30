import asyncio
from pickle import dumps, loads
import secrets
from dpss.polynomial import polynomials_over
from dpss.broadcast.optqrbc import optqrbc
from dpss.utils.misc import wrap_send, subscribe_recv
from pypairing import G1 as blsG1, blsmultiexp
from pypairing import curve25519multiexp
from dpss.utils.misc import print_exception_callback

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
logger.setLevel(logging.DEBUG)

class ACSS_DCR:
    #@profile
    def __init__(
            self, public_keys, private_key, g, receiver_ids, t, deg, my_id, G1, ZR, send, recv):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.receiver_ids, self.t, self.deg, self.my_id = tuple(receiver_ids), t, deg, my_id
        self.g, self.G1, self.ZR = g, G1, ZR
        self.n = len(receiver_ids)
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache()
        if my_id in receiver_ids:
            self.output_queue = asyncio.Queue()
            self.dual_codes, self.dual_codes_with_zero= {}, {}
            # assume the same dual code can be used multiple times safely
            #self.dual_codes[(deg,self.receiver_ids)] = self.gen_dual_code(self.receiver_ids,deg,self.poly)
            self.dual_codes_with_zero[(deg,self.receiver_ids)] = self.gen_dual_code_with_zero(self.receiver_ids,deg,self.poly)

            if G1 is blsG1:
                self.multiexp = blsmultiexp
            else:
                self.multiexp = curve25519multiexp
            print("setup done")
        
    
    def kill(self):
        self.subscribe_recv_task.cancel()
        #self.rbc_task.cancel()

    #@profile
    def _process_avss_msg(self, avss_id, dealer_id, rbc_msg):
        comms, encryptions, _ = loads(rbc_msg)
        share = self.ZR(self.private_key.raw_decrypt(encryptions[self.receiver_ids.index(self.my_id)]))
        #asyncio.run_coroutine_threadsafe(self.output_queue.put_nowait((dealer_id, avss_id, [int(share)], comms)), asyncio.get_event_loop())
        self.output_queue.put_nowait((dealer_id, avss_id, [int(share)], comms))
        print("player " + str(self.my_id)+ " output in acss " + str(dealer_id) + ". Queuesize = " + str(self.output_queue.qsize()))

    
    def check_degree(self, claimed_degree, commitments):
        if (claimed_degree, self.receiver_ids) not in self.dual_codes.keys():
            self.dual_codes[(claimed_degree, self.receiver_ids)] = self.gen_dual_code(self.receiver_ids, claimed_degree, self.poly)

        dual_code = self.dual_codes[(claimed_degree, self.receiver_ids)]
        check = self.multiexp(commitments, dual_code)

        return check == self.g ** 0

    #for commitment lists that include g**phi(0)
    def check_degree_with_zero(self, claimed_degree, commitments):
        if (claimed_degree, self.receiver_ids) not in self.dual_codes_with_zero.keys():
            self.dual_codes_with_zero[(claimed_degree, self.receiver_ids)] = self.gen_dual_code_with_zero(self.receiver_ids, claimed_degree, self.poly)

        dual_code = self.dual_codes_with_zero[(claimed_degree, self.receiver_ids)]
        check = self.multiexp(commitments, dual_code)

        return check == self.g ** 0

    #todo: degree should be an instance arg
    def _get_dealer_msg(self, secret):
        phi = self.poly.random(self.deg, secret)
        outputs = [self.prove_knowledge_of_encrypted_dlog(self.g, phi(id+1), self.public_keys[id]) for id in self.receiver_ids]
        comms, encryptions, proofs = [[outputs[i][j] for i in range(len(self.receiver_ids))] for j in range(3)]
        comms = [self.g ** secret] + comms
        return dumps([comms, encryptions, proofs])

    #@profile
    async def avss(self, avss_id, values=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share secrets."
        # If `secret` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id, f"Player {self.my_id}: Where's your secret, dealer?"
        assert type(avss_id) is int, "invalid avss_id"

        logger.debug(
            "[%d] Starting AVSS. Id: %s, Dealer Id: %d",
            self.my_id,
            avss_id,
            dealer_id,
        )

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-R"

        broadcast_msg = None
        if self.my_id == dealer_id:
            # broadcast_msg: phi & public key for reliable broadcast
            # dispersal_msg_list: the list of payload z
            secret = values[0]
            broadcast_msg = self._get_dealer_msg(secret)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            comms, encryptions, proofs = loads(_m)
            print("player " + str(self.my_id)+ " rbc done in acss " + str(dealer_id))
            #Check 0: make sure everything is the correct length
            n = len(self.receiver_ids)
            if len(comms) is not n or len(encryptions) is not n or len(proofs) is not n:
                print("len check failed")
                return False
            #Check 1: verify that polynomial is degree d
            print("checkin degreeee")
            if not self.check_degree(self.deg, comms):
                print("degree check failed")
                return False
            
            #Check 2: check each encryption proof is valid
            for i in range(self.n):
                if not self.verify_knowledge_of_discrete_log(self.public_keys[self.receiver_ids[i]], self.g, comms[i], encryptions[i], proofs[i]):
                    print("encryption proof failed!")
                    return False
            return True
        
        async def predicate_with_zero(_m):
            comms, encryptions, proofs = loads(_m)
            print("player " + str(self.my_id)+ " rbc checking in acss " + str(dealer_id))
            #Check 0: make sure everything is the correct length
            n = len(self.receiver_ids)
            if len(comms) is not n+1 or len(encryptions) is not n or len(proofs) is not n:
                print("len check failed")
                return False
            #Check 1: verify that polynomial is degree d
            print("checkin degreeee")
            if not self.check_degree_with_zero(self.deg, comms):
                print("degree check failed")
                return False
            
            #Check 2: check each encryption proof is valid
            for i in range(self.n):
                if not self.verify_knowledge_of_discrete_log(self.public_keys[self.receiver_ids[i]], self.g, comms[i+1], encryptions[i], proofs[i]):
                    print("encryption proof failed!")
                    return False
            return True

        output = asyncio.Queue()
        rbc_task = asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.receiver_ids,
            self.t,
            dealer_id,
            predicate_with_zero,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))  # (# noqa: E501)
        rbc_task.add_done_callback(print_exception_callback)
        if self.my_id not in self.receiver_ids:
            await rbc_task
            return

        rbc_msg = await output.get()
        print("player " + str(self.my_id)+ " rbc done in acss " + str(dealer_id))
        # avss processing
        self._process_avss_msg(avss_id, dealer_id, rbc_msg)
        #self.subscribe_recv_task.cancel()

    def prove_knowledge_of_encrypted_dlog(self, g, x, pk, g_to_the_x=None):
        if g_to_the_x is None:
            Y = g**x
        else:
            Y = g_to_the_x
        r = pk.get_random_lt_n()
        c = pk.encrypt(int(x), r_value=r).ciphertext(be_secure=False)
        # Todo: see if this limitation is libarary-specific. Maybe use a slightly larget N? 
        u = pk.get_random_lt_n() // 3 # maximum valid value we can encrypt
        T = g ** self.ZR(u)
        s = pk.get_random_lt_n()
        e_u = pk.encrypt(u, r_value=s)

        e = self.ZR.hash(dumps([pk, g, Y, c, T, e_u.ciphertext(be_secure=False)]))
        z = u + int(e)*int(x)
        w = (pow(r, int(e), pk.nsquare) * s) % pk.nsquare
        proof = [T, z, e_u, w]
        return [Y, c, proof]

    def verify_knowledge_of_discrete_log(self, pk, g, Y, c, proof):
        T, z, e_u, w = proof
        e = self.ZR.hash(dumps([pk, g, Y, c, T, e_u.ciphertext(be_secure=False)]))
        # be_secure is default true and adds a randomizing factor to the ciphertext as a failsafe. 
        # we need it turned off so that the calculations will be correct
        c_e = pow(c, int(e), pk.nsquare)
        return T == (g ** z) * (Y ** (-e)) and (e_u.ciphertext(be_secure=False) * c_e) % pk.nsquare == pk.encrypt(z, r_value=w).ciphertext(be_secure=False)

    def gen_dual_code(self, receiver_ids, degree, poly):
        def get_vi(i, receiver_ids):
            out = self.ZR(1)
            for j in receiver_ids:
                if j != i:
                    out = out / (i-j)
            return out
        q = poly.random(len(receiver_ids) -degree -2)
        q_evals = [q(id) for id in receiver_ids]
        return [q_evals[i] * get_vi(receiver_ids[i], receiver_ids) for i in range(len(receiver_ids))]

    def gen_dual_code_with_zero(self, receiver_ids, degree, poly):
        def get_vi(i, ids):
            out = self.ZR(1)
            for j in ids:
                if j != i:
                    out = out / (i-j)
            return out
        #player -1 would have the share phi(0)
        ids = [-1] + list(receiver_ids)
        q = poly.random(len(ids) -degree -2)
        q_evals = [q(id) for id in ids]
        return [q_evals[i] * get_vi(ids[i], ids) for i in range(len(ids))]
        