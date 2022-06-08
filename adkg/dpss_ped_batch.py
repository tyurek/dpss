from adkg.utils.misc import wrap_send, subscribe_recv
from adkg.acss_dcr_ped_batch import ACSS_DCR_PED_BATCH
from adkg.broadcast.tylerba_beacon import tylerba
from adkg.batch_reconstruct_ped_rust import batch_reconstruct_ped
from adkg.utils.misc import print_exception_callback
from pypairing import curve25519dotprod, dotprod, G1 as blsG1

import asyncio
from math import ceil
from pickle import dumps

class DPSSMessageType:
    SENDCOMMS = 1
    RBC = 2
    ABA = 3
    SHARES = 4
    SEND_BLINDED_SHARES = 5

def add_comm_list(list1, list2):
    if len(list1) != len(list2):
        print("warning: unmatched list sizes")
    return [list1[i] * list2[i] for i in range(len(min(list1, list2)))]

def sub_comm_list(list1, list2):
    if len(list1) != len(list2):
        print("warning: unmatched list sizes")
    return [list1[i] / list2[i] for i in range(len(min(list1, list2)))]

def sum_comm_lists(lists):
    out = lists[0]
    for i in range(len(lists)-1):
        out = add_comm_list(out, lists[i+1])
    return out

def mul_comm_list(comms, num):
    return [comms[i].pow(num) for i in range(len(comms))]

def get_lagrange_coeffs(x_list, target, ZR):
    size = len(x_list)
    out = []
    for i in range(size):
        num = ZR(1)
        denom = ZR(1)
        for j in range(size):
            if i == j:
                continue
            num *= target-x_list[j]
            denom *= x_list[i]-x_list[j]
        out.append(num/denom)
    return out

#committee has t, ids, degree
class DPSS_PED_BATCH:
    def __init__(self, public_keys, private_key, g, h, old_committee, new_committee, my_id, G1, ZR, send, recv):
        #init
        self.old_committee, self.new_committee, self.my_id = old_committee, new_committee, my_id
        self.g, self.h = g, h
        self.sessionvars = {}
        self.public_keys, self.private_key = public_keys, private_key
        self.G1, self.ZR = G1, ZR
        matrix_n = len(old_committee['ids']) - old_committee['t']
        self.matrix = [ [ZR.hash(dumps(i))**j for j in range(matrix_n)] for i in range(matrix_n)]
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send
        
        if G1 is blsG1:
            self.dotprod = dotprod
        else:
            self.dotprod = curve25519dotprod
        
        self.output_queue = asyncio.Queue()
        self.acss_outputs = {}
        self.acss_signal = asyncio.Event()

    async def dpss(self, dpss_id, values=None, comms=None):
        batch_comms = comms
        dpsstag = f"{dpss_id}-DPSS"
        send, recv = self.get_send(dpsstag), self.subscribe_recv(dpsstag)
        #should this need a different tag?
        acsstag = f"{dpss_id}-ACSS"
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        acss = ACSS_DCR_PED_BATCH(self.public_keys, self.private_key, self.g, self.h, self.new_committee['ids'], self.new_committee['t'], self.new_committee['degree'], self.my_id, self.G1, self.ZR, acsssend, acssrecv)
        #send commits (all to all)
        if self.my_id in self.old_committee['ids']:
            assert values is not None and comms is not None, "Missing required share/comms"
            #for id in self.new_committee['ids']:
                #todo: need more efficient method for batch-amortized
            #    send(id, [DPSSMessageType.SENDCOMMS, comms])

            rand_batchsize = ceil(len(values[0]) / (len(self.old_committee['ids']) - (2*self.old_committee['t'])))
            randvalues = ([self.ZR.rand() for b in range(rand_batchsize)], [self.ZR.rand() for b in range(rand_batchsize)])

            acsstag_oc = f"{dpss_id}-oc-ACSS"
            acsssend_oc, acssrecv_oc = self.get_send(acsstag_oc), self.subscribe_recv(acsstag_oc)
            acss_oc = ACSS_DCR_PED_BATCH(self.public_keys, self.private_key, self.g, self.h, self.old_committee['ids'], self.old_committee['t'], self.old_committee['degree'], self.my_id, self.G1, self.ZR, acsssend_oc, acssrecv_oc)
            avss_task_oc = asyncio.create_task(acss_oc.avss(self.my_id, values=randvalues, dealer_id=self.my_id))
            avss_task_oc.add_done_callback(print_exception_callback)
            
            #receive from old_committee n-1 times
            avss_recv_tasks = [asyncio.create_task(acss_oc.avss(id, dealer_id=id)) for id in self.old_committee['ids'] if id != self.my_id]
            _ = [task.add_done_callback(print_exception_callback) for task in avss_recv_tasks]

            #deal for new committee too
            avss_task = asyncio.create_task(acss.avss(self.my_id, values=randvalues, dealer_id=self.my_id))
            avss_task.add_done_callback(print_exception_callback)
            
            #todo (future): merge this horrid copypaste
            ba_inputs = {id: asyncio.Queue() for id in self.old_committee['ids']}
            ba_outputs = {id: asyncio.Queue() for id in self.old_committee['ids']}
            ba_outputs = {}
            ba_outqueue = asyncio.Queue()
            def gen_aba_task(id):
                abatag = f"{dpss_id}-ABA-{id}"
                asend, arecv = self.get_send(abatag), self.subscribe_recv(abatag)
                def broadcast(m):
                    #for id2 in self.old_committee['ids'] + self.new_committee['ids']:
                    for id2 in self.old_committee['ids'] + self.new_committee['ids']:
                        asend(id2, m)
                #task = asyncio.create_task(tylerba(abatag, self.my_id, self.old_committee['ids'] + self.new_committee['ids'], self.old_committee['t'] + self.new_committee['t'], None, ba_inputs[id].get, ba_outqueue.put_nowait, broadcast, arecv))
                task = asyncio.create_task(tylerba(abatag, self.my_id, self.old_committee['ids'], self.old_committee['t'], None, ba_inputs[id].get, ba_outqueue.put_nowait, broadcast, arecv))
                task.add_done_callback(print_exception_callback)
                return task
            
            ba_tasks = [gen_aba_task(id) for id in self.old_committee['ids']]
            acss_signal = asyncio.Event()
            acss_signal.clear()
            
            async def acss_updater():
                while len(self.acss_outputs.keys()) < len(self.old_committee['ids']):
                    print("player " + str(self.my_id)+ " is waiting for acss outputs ")
                    entry = await acss_oc.output_queue.get()
                    shares_i, shares_i_hat, batch_c_i, sender_i = entry[2], entry[3], entry[4], entry[0]
                    print("player " + str(self.my_id)+ " got acss " + str(sender_i))
                    
                    self.acss_outputs[sender_i] = (shares_i, shares_i_hat, batch_c_i)
                    #assuming multiple inputs won't break anything.
                    ba_inputs[sender_i].put_nowait(1)
                    acss_signal.set()
            
            acss_update_task = asyncio.create_task(acss_updater())
            acss_update_task.add_done_callback(print_exception_callback)
            
            while len(ba_outputs.keys()) < len(self.old_committee['ids']):
                abatag, ba_out = await ba_outqueue.get()
                print(f"{self.my_id} got an aba output!")
                #assumes the tag looks something like f"{dpss_id}-ABA-{id}"
                id = int(abatag.split('-')[-1])
                ba_outputs[id] = ba_out
                if len(ba_outputs.keys()) == len(self.old_committee['ids']) - self.old_committee['t']:
                    for id in self.old_committee['ids']:
                        if id not in self.acss_outputs.keys():
                            ba_inputs[id].put_nowait(0)
                
            print("before subset")
            print(ba_outputs.keys())
            subset = [ba_outputs[id] for id in self.old_committee['ids']]
            print("aftter subset")
            i = 0
            subsubset = set()
            reset = False
            while len(subsubset) < len(self.old_committee['ids']) - self.old_committee['t']:
                if subset[i] == 1:
                    subsubset.add(self.old_committee['ids'][i])
                    i +=1
            
            #wait for any acss instances we know will still finish
            for id in subsubset:
                while id not in self.acss_outputs.keys():
                    await acss_signal.wait()
                    acss_signal.clear()

            subsubset_list = sorted(subsubset)
            
            #shouldn't this be n-t-t?
            n_minus_t = len(self.old_committee['ids']) - self.old_committee['t']
            n_minus_2t = n_minus_t - self.old_committee['t']
            global_randoms = []
            global_randoms_hat = []
            global_random_comms = []
            for b in range(rand_batchsize):
                local_randoms = [ self.acss_outputs[sender_i][0][b] for sender_i in subsubset_list]
                local_randoms_hat = [ self.acss_outputs[sender_i][1][b] for sender_i in subsubset_list]
                local_comms = [ self.acss_outputs[sender_i][2][b] for sender_i in subsubset_list]
                global_randoms += [ self.dotprod(self.matrix[i], local_randoms) for i in range(n_minus_2t)]
                global_randoms_hat += [ self.dotprod(self.matrix[i], local_randoms_hat) for i in range(n_minus_2t)]
                global_random_comms += [sum_comm_lists([mul_comm_list(local_comms[j], self.matrix[i][j]) for j in range(n_minus_t)]) for i in range(n_minus_2t)]

            blinded_shares = [values[0][i] + global_randoms[i] for i in range(len(values[0]))]
            blinded_shares_hat = [values[1][i] + global_randoms_hat[i] for i in range(len(values[0]))]
            br_comms = [add_comm_list(global_random_comms[i], batch_comms[i]) for i in range(len(batch_comms))]
            
            brtag = f"{dpss_id}-DPSS-BR"
            sendbr, recvbr = self.get_send(brtag), self.subscribe_recv(brtag)
            br_output = asyncio.Queue()
            task = asyncio.create_task(batch_reconstruct_ped(True, self.old_committee['ids'], self.my_id, self.old_committee['t'], self.new_committee['degree'], self.g, self.h, br_output.put_nowait, self.ZR, self.G1, sendbr, recvbr, shares=blinded_shares, shares_hat=blinded_shares_hat, comms=br_comms))
            task.add_done_callback(print_exception_callback)
            
            blinded_shares, blinded_shares_hat = await br_output.get()
            for id in self.new_committee['ids']:
                #todo: need more efficient method for batch-amortized
                send(id, [DPSSMessageType.SEND_BLINDED_SHARES, [blinded_shares, blinded_shares_hat, subsubset_list]])
            
        else:
            avss_recv_tasks = [asyncio.create_task(acss.avss(id, dealer_id=id)) for id in self.old_committee['ids']]
            _ = [task.add_done_callback(print_exception_callback) for task in avss_recv_tasks]
            #modify acss to allow you to use the same instance for multiple sessions, then read output queue d+1 times
            '''
            received_comms = {}
            comm_tally = {}
            batch_comms = None
            while True:
                sender, dpss_msg = await recv()
                if dpss_msg[0] == DPSSMessageType.SENDCOMMS and sender not in received_comms.keys():
                    received_comms[sender] = dpss_msg[1]
                    #todo: faster hashable than string...
                    comm_tally[str(dpss_msg[1])] = comm_tally.get(str(dpss_msg[1]),0)+1
                    if comm_tally[str(dpss_msg[1])] == self.old_committee['t'] + 1:
                        batch_comms = dpss_msg[1]
                        break
            '''
            '''
            ba_inputs = {id: asyncio.Queue() for id in self.old_committee['ids']}
            ba_outputs = {id: asyncio.Queue() for id in self.old_committee['ids']}
            ba_outputs = {}
            ba_outqueue = asyncio.Queue()
            def gen_aba_task(id):
                abatag = f"{dpss_id}-ABA-{id}"
                asend, arecv = self.get_send(abatag), self.subscribe_recv(abatag)
                def broadcast(m):
                    for id2 in self.old_committee['ids'] + self.new_committee['ids']:
                        asend(id2, m)
                task = asyncio.create_task(tylerba(abatag, self.my_id, self.old_committee['ids'] + self.new_committee['ids'], self.old_committee['t'] + self.new_committee['t'], None, ba_inputs[id].get, ba_outqueue.put_nowait, broadcast, arecv))
                task.add_done_callback(print_exception_callback)
                return task
            
            ba_tasks = [gen_aba_task(id) for id in self.old_committee['ids']]
            '''
            acss_signal = asyncio.Event()
            acss_signal.clear()
            
            async def acss_updater():
                while len(self.acss_outputs.keys()) < len(self.old_committee['ids']):
                    print("player " + str(self.my_id)+ " is waiting for acss outputs ")
                    entry = await acss.output_queue.get()
                    shares_i, shares_i_hat, batch_c_i, sender_i = entry[2], entry[3], entry[4], entry[0]
                    print("player " + str(self.my_id)+ " got acss " + str(sender_i))
                    
                    self.acss_outputs[sender_i] = (shares_i, shares_i_hat, batch_c_i)
                    #assuming multiple inputs won't break anything.
                    #ba_inputs[sender_i].put_nowait(1)
                    acss_signal.set()
            
            acss_update_task = asyncio.create_task(acss_updater())
            acss_update_task.add_done_callback(print_exception_callback)
            
            '''
            while len(ba_outputs.keys()) < len(self.old_committee['ids']):
                print("player " + str(self.my_id)+ " is waiting for ba outputs ")
                abatag, ba_out = await ba_outqueue.get()
                print("player " + str(self.my_id)+ " finished aba " + abatag + ". Total finished: " + str(len(ba_outputs.keys())))
                #assumes the tag looks something like f"{dpss_id}-ABA-{id}"
                id = int(abatag.split('-')[-1])
                ba_outputs[id] = ba_out
                if len(ba_outputs.keys()) == len(self.old_committee['ids']) - self.old_committee['t']:
                    for id in self.old_committee['ids']:
                        if id not in self.acss_outputs.keys():
                            ba_inputs[id].put_nowait(0)
                
            print("before subset")
            print(ba_outputs.keys())
            subset = [ba_outputs[id] for id in self.old_committee['ids']]
            print("aftter subset")
            i = 0
            subsubset = set()
            reset = False
            while len(subsubset) < len(self.old_committee['ids']) - self.old_committee['t']:
                if subset[i] == 1:
                    subsubset.add(self.old_committee['ids'][i])
                    i +=1
            
            '''
            received_blinds = {}
            blind_tally = {}
            batch_blinds = None
            
            while True:
                sender, dpss_msg = await recv()
                if dpss_msg[0] == DPSSMessageType.SEND_BLINDED_SHARES and sender not in received_blinds.keys():
                    received_blinds[sender] = dpss_msg[1]
                    #todo: faster hashable than string...
                    blind_tally[str(dpss_msg[1])] = blind_tally.get(str(dpss_msg[1]),0)+1
                    if blind_tally[str(dpss_msg[1])] == self.old_committee['t'] + 1:
                        batch_blinds = dpss_msg[1]
                        break
            
            blinded_shares, blinded_shares_hat, subsubset_list = batch_blinds

            #wait for any acss instances we know will still finish
            for id in subsubset_list:
                while id not in self.acss_outputs.keys():
                    await acss_signal.wait()
                    acss_signal.clear()

            n_minus_t = len(self.old_committee['ids']) - self.old_committee['t']
            n_minus_2t = n_minus_t - self.old_committee['t']
            global_randoms = []
            global_randoms_hat = []
            global_random_comms = []
            
            #every player in the subset should have dealt the same number of random values, so just use the length of any
            print("presus")
            rand_batchsize = len(self.acss_outputs[next(iter(subsubset_list))][0])
            print("postsus")
            
            for b in range(rand_batchsize):
                local_randoms = [ self.acss_outputs[sender_i][0][b] for sender_i in subsubset_list]
                local_randoms_hat = [ self.acss_outputs[sender_i][1][b] for sender_i in subsubset_list]
                local_comms = [ self.acss_outputs[sender_i][2][b] for sender_i in subsubset_list]
                print("woooooah we're halfway there")
                global_randoms += [ self.dotprod(self.matrix[i], local_randoms) for i in range(n_minus_2t)]
                global_randoms_hat += [ self.dotprod(self.matrix[i], local_randoms_hat) for i in range(n_minus_2t)]
                print("woah ho")
                
                #you're using comms for new_committee randomness here
                #first_global = sum_comm_lists([mul_comm_list(local_comms[j], self.matrix[0][j]) for j in range(n_minus_t)])
                global_random_comms += [sum_comm_lists([mul_comm_list(local_comms[j], self.matrix[i][j]) for j in range(n_minus_t)]) for i in range(n_minus_2t)]
                
            print("postloop")
            
            '''
            
            br_comms = [add_comm_list(global_random_comms[i], batch_comms[i]) for i in range(len(batch_comms))]
            
            brtag = f"{dpss_id}-DPSS-BR"
            sendbr, recvbr = self.get_send(brtag), self.subscribe_recv(brtag)
            br_output = asyncio.Queue()
            task = asyncio.create_task(batch_reconstruct_ped(False, self.new_committee['ids'], self.my_id, self.new_committee['t'], self.new_committee['degree'], self.g, self.h, br_output.put_nowait, self.ZR, self.G1, sendbr, recvbr, comms=br_comms))
            task.add_done_callback(print_exception_callback)
            blinded_shares, blinded_shares_hat = await br_output.get()
            '''
            
            shares = [blinded_shares[i] - global_randoms[i] for i in range(len(blinded_shares))]
            shares_hat = [blinded_shares_hat[i] - global_randoms_hat[i] for i in range(len(blinded_shares_hat))]
            
            #todo: calc outcom
            outcom = None
            blind_comms = [self.g**blinded_shares[i] * self.h**blinded_shares_hat[i] for i in range(len(blinded_shares))]
            outcom = [ sub_comm_list([blind_comms[i] for j in range(len(global_random_comms[i]))], global_random_comms[i]) for i in range(len(blinded_shares))]
            self.output_queue.put_nowait((dpss_id, shares, shares_hat, outcom))

        print(f"Player {self.my_id} has been terminated")
