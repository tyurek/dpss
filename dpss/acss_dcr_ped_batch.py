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

class ACSS_DCR_PED_BATCH:
    #@profile
    def __init__(
            self, public_keys, private_key, g, h, receiver_ids, t, deg, my_id, G1, ZR, send, recv):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.receiver_ids, self.t, self.deg, self.my_id = tuple(receiver_ids), t, deg, my_id
        self.g, self.h, self.G1, self.ZR = g, h, G1, ZR
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
        #proofs were checked earlier
        biglist = loads(rbc_msg)
        relative_id = self.receiver_ids.index(self.my_id)
        batch_comms = [entry[0] for entry in biglist]
        assert type(batch_comms[0]) is list
        batch_shares = [self.ZR(self.private_key.raw_decrypt(entry[1][relative_id])) for entry in biglist]
        batch_shares_hat = [self.ZR(self.private_key.raw_decrypt(entry[2][relative_id])) for entry in biglist]
        
        self.output_queue.put_nowait((dealer_id, avss_id, batch_shares, batch_shares_hat, batch_comms))
        #print("player " + str(self.my_id)+ " output in acss " + str(dealer_id) + ". Queuesize = " + str(self.output_queue.qsize()))

    #for commitment lists that include g**phi(0)
    def check_degree_with_zero(self, claimed_degree, commitments):
        if (claimed_degree, self.receiver_ids) not in self.dual_codes_with_zero.keys():
            self.dual_codes_with_zero[(claimed_degree, self.receiver_ids)] = self.gen_dual_code_with_zero(self.receiver_ids, claimed_degree, self.poly)

        dual_code = self.dual_codes_with_zero[(claimed_degree, self.receiver_ids)]
        check = self.multiexp(commitments, dual_code)

        return check == self.g ** 0

    #todo: degree should be an instance arg
    def _get_dealer_msg(self, secrets, secrets_hat):
        assert len(secrets) == len(secrets_hat)
        outmsg = []
        for secret, secret_hat in zip(secrets, secrets_hat):
            phi, phi_hat = self.poly.random(self.deg, secret), self.poly.random(self.deg, secret_hat)
            outputs = [self.prove_knowledge_of_encrypted_ped(self.g, self.h, phi(id+1), phi_hat(id+1), self.public_keys[id]) for id in self.receiver_ids]
            comms, encryptions, encryptions_hat, proofs = [[outputs[i][j] for i in range(len(self.receiver_ids))] for j in range(4)]
            comms = [self.g ** secret * self.h ** secret_hat] + comms
            outmsg.append([comms, encryptions, encryptions_hat, proofs])
        return dumps(outmsg)

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
            secrets, secrets_hat = values[0], values[1]
            broadcast_msg = self._get_dealer_msg(secrets, secrets_hat)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)
        
        async def predicate_with_zero(_m):
            biglist = loads(_m)
            #print("player " + str(self.my_id)+ " rbc checking in acss " + str(dealer_id))
            #Check 0: make sure everything is the correct length
            n = len(self.receiver_ids)
            for item in biglist:
                comms, encryptions, encryptions_hat, proofs = item
                if len(comms) is not n+1 or len(encryptions) is not n or len(encryptions_hat) is not n or len(proofs) is not n:
                    print("len check failed")
                    return False
                #Check 1: verify that polynomial is degree d
                #print("checkin degreeee")
                if not self.check_degree_with_zero(self.deg, comms):
                    print("degree check failed")
                    return False
                
                #Check 2: check each encryption proof is valid
                for i in range(self.n):
                    if not self.verify_knowledge_of_encrypted_ped(self.public_keys[self.receiver_ids[i]], self.g, self.h, comms[i+1], encryptions[i], encryptions_hat[i], proofs[i]):
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

    def prove_knowledge_of_encrypted_ped(self, g, h, x, x_hat, pk, ped_com=None):
        if ped_com is None:
            Y = g**x * h**x_hat
        else:
            Y = ped_com
        r, r_hat = pk.get_random_lt_n(), pk.get_random_lt_n()
        # be_secure is default true and adds a randomizing factor to the ciphertext as a failsafe. 
        # we need it turned off so that the calculations will be correct
        c, c_hat = pk.encrypt(int(x), r_value=r).ciphertext(be_secure=False), pk.encrypt(int(x_hat), r_value=r_hat).ciphertext(be_secure=False)
        # Todo: see if this limitation is libarary-specific. Maybe use a slightly larget N? 
        u, u_hat = pk.get_random_lt_n() // 3, pk.get_random_lt_n() // 3 # maximum valid value we can encrypt
        T = g ** self.ZR(u) * h ** self.ZR(u_hat)
        s, s_hat = pk.get_random_lt_n(), pk.get_random_lt_n()
        e_u, e_u_hat = pk.encrypt(u, r_value=s), pk.encrypt(u_hat, r_value=s_hat)

        e = self.ZR.hash(dumps([pk, g, h, Y, c, c_hat, T, e_u.ciphertext(be_secure=False), e_u_hat.ciphertext(be_secure=False)]))
        z, z_hat = u + int(e)*int(x), u_hat + int(e)*int(x_hat)
        w, w_hat= (pow(r, int(e), pk.nsquare) * s) % pk.nsquare, (pow(r_hat, int(e), pk.nsquare) * s_hat) % pk.nsquare
        proof = [T, z, z_hat, e_u, e_u_hat, w, w_hat]
        return [Y, c, c_hat, proof]

    def verify_knowledge_of_encrypted_ped(self, pk, g, h, Y, c, c_hat, proof):
        T, z, z_hat, e_u, e_u_hat, w, w_hat = proof
        e = self.ZR.hash(dumps([pk, g, h, Y, c, c_hat, T, e_u.ciphertext(be_secure=False), e_u_hat.ciphertext(be_secure=False)]))
        c_e, c_e_hat = pow(c, int(e), pk.nsquare), pow(c_hat, int(e), pk.nsquare)
        return T == (g ** z) *  (h ** z_hat) * (Y ** (-e)) and (e_u.ciphertext(be_secure=False) * c_e) % pk.nsquare == pk.encrypt(z, r_value=w).ciphertext(be_secure=False) and (e_u_hat.ciphertext(be_secure=False) * c_e_hat) % pk.nsquare == pk.encrypt(z_hat, r_value=w_hat).ciphertext(be_secure=False)

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
        