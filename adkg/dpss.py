from adkg.utils.misc import wrap_send, subscribe_recv
from adkg.acss_dcr2 import ACSS_DCR
from adkg.broadcast.tylerba_beacon import tylerba
from adkg.utils.misc import print_exception_callback


import asyncio

class DPSSMessageType:
    SENDCOMMS = 1
    RBC = 2
    ABA = 3

def add_comm_list(list1, list2):
    return [list1[i] * list2[i] for i in range(len(list1))]

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
class DPSS:
    def __init__(self, public_keys, private_key, g, old_committee, new_committee, my_id, G1, ZR, send, recv):
        #init
        self.old_committee, self.new_committee, self.my_id = old_committee, new_committee, my_id
        self.g = g
        self.sessionvars = {}
        self.public_keys, self.private_key = public_keys, private_key
        self.G1, self.ZR = G1, ZR
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send
        
        if my_id in new_committee['ids']:
            self.output_queue = asyncio.Queue()
            self.acss_outputs = {}
            self.acss_signal = asyncio.Event()

    async def dpss(self, dpss_id, share=None, comms=None):
        dpsstag = f"{dpss_id}-DPSS"
        send, recv = self.get_send(dpsstag), self.subscribe_recv(dpsstag)
        #should this need a different tag?
        acsstag = f"{dpss_id}-ACSS"
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        acss = ACSS_DCR(self.public_keys, self.private_key, self.g, self.new_committee['ids'], self.new_committee['t'], self.new_committee['degree'], self.my_id, self.G1, self.ZR, acsssend, acssrecv)
        #send commits (all to all)
        if self.my_id in self.old_committee['ids']:
            assert share is not None and comms is not None, "Missing required share/comms"
            for id in self.new_committee['ids']:
                #todo: need more efficient method for batch-amortized
                #how about: send hash of all commlists, disperse all commlists, a receiver picks a dispersal originating from a hash that has t+1 votes
                #^this can fail a few times, has bad worst case. Avoidable if erasure coding is deterministic
                #^^ what if adversary sends the same share to one node but other shares are wrong so reconstruction fails
                send(id, [DPSSMessageType.SENDCOMMS, comms])
            #subprotocol send...
            avss_task = asyncio.create_task(acss.avss(self.my_id, values=[share], dealer_id=self.my_id))
            avss_task.add_done_callback(print_exception_callback)
        else:
            avss_tasks = [asyncio.create_task(acss.avss(id, dealer_id=id)) for id in self.old_committee['ids']]
            _ = [task.add_done_callback(print_exception_callback) for task in avss_tasks]
            #modify acss to allow you to use the same instance for multiple sessions, then read output queue d+1 times
            received_comms = {}
            comm_tally = {}
            comms = None
            while True:
                sender, dpss_msg = await recv()
                if dpss_msg[0] == DPSSMessageType.SENDCOMMS and sender not in received_comms.keys():
                    received_comms[sender] = dpss_msg[1]
                    #todo: faster hashable than string...
                    comm_tally[str(dpss_msg[1])] = comm_tally.get(str(dpss_msg[1]),0)+1
                    if comm_tally[str(dpss_msg[1])] == self.old_committee['t'] + 1:
                        comms = dpss_msg[1]
                        break
                        
            shares, comm_vecs = [], []
            ba_inputs = {id: asyncio.Queue() for id in self.old_committee['ids']}
            ba_outputs = {id: asyncio.Queue() for id in self.old_committee['ids']}
            ba_outputs = {}
            ba_outqueue = asyncio.Queue()
            def gen_aba_task(id):
                abatag = f"{dpss_id}-ABA-{id}"
                asend, arecv = self.get_send(abatag), self.subscribe_recv(abatag)
                def broadcast(m):
                    for id2 in self.new_committee['ids']:
                        asend(id2, m)
                task = asyncio.create_task(tylerba(abatag, self.my_id, self.new_committee['ids'], self.new_committee['t'], None, ba_inputs[id].get, ba_outqueue.put_nowait, broadcast, arecv))
                task.add_done_callback(print_exception_callback)
                return task
            
            ba_tasks = [gen_aba_task(id) for id in self.old_committee['ids']]
            acss_signal = asyncio.Event()
            acss_signal.clear()
            
            async def acss_updater():
                while len(self.acss_outputs.keys()) < len(self.old_committee['ids']):
                    print("player " + str(self.my_id)+ " is waiting for acss outputs ")
                    entry = await acss.output_queue.get()
                    share_i, c_i, sender_i = entry[2][0], entry[3], entry[0]
                    print("player " + str(self.my_id)+ " got acss " + str(sender_i))
                    
                    idx_i = self.old_committee['ids'].index(sender_i)
                    #assuming comms[0] is g**s
                    if comms[idx_i+1] == c_i[0]:
                        self.acss_outputs[sender_i] = (share_i, c_i)
                        #assuming multiple inputs won't break anything.
                        ba_inputs[sender_i].put_nowait(1)
                        acss_signal.set()
            
            acss_update_task = asyncio.create_task(acss_updater())
            acss_update_task.add_done_callback(print_exception_callback)
            
            while len(ba_outputs.keys()) < len(self.old_committee['ids']):
                abatag, ba_out = await ba_outqueue.get()
                #assumes the tag looks something like f"{dpss_id}-ABA-{id}"
                id = int(abatag.split('-')[-1])
                ba_outputs[id] = ba_out
                if len(ba_outputs.keys()) == self.new_committee['degree'] + 1:
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
            while len(subsubset) <= self.new_committee['degree']:
                if subset[i] == 1:
                    subsubset.add(self.old_committee['ids'][i])
                    i +=1
            
            #wait for any acss instances we know will still finish
            for id in subsubset:
                while id not in self.acss_outputs.keys():
                    await acss_signal.wait()
                    acss_signal.clear()
            
            
            shares = [ (sender_i + 1, self.acss_outputs[sender_i][0]) for sender_i in subsubset]
            comm_vecs = [ (sender_i + 1, self.acss_outputs[sender_i][1]) for sender_i in subsubset]
            xlist = [share[0] for share in shares]
            lc = get_lagrange_coeffs(xlist, 0, self.ZR)
            print("lagrange worked")
            out_share, out_comm = self.ZR(0), [self.G1.identity() for i in range(len(comm_vecs[0][1]))]
            for i in range(len(lc)):
                out_share += lc[i] * shares[i][1]
                #I think this won't give commits to the right shares
                print("trying the comm stuff now")
                out_comm = add_comm_list(out_comm, mul_comm_list(comm_vecs[i][1], lc[i]))
            self.output_queue.put_nowait((dpss_id, [out_share], [out_comm]))

        print(f"Player {self.my_id} has been terminated")
