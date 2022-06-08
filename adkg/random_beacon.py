from random import randint
import asyncio

class RandomBeacon:
    def __init__(self, threshold, broadcast, recv):
        self.threshold, self.broadcast, self.recv = threshold, broadcast, recv
        self.sessions = {}
    
    async def run(self):
        while True:
            sender, sid = await self.recv()
            self.sessions[sid] = self.sessions.get(sid, 0) + 1
            if self.sessions[sid] == self.threshold + 1:
                b = randint(0,1)
                self.broadcast((sid, b))
        