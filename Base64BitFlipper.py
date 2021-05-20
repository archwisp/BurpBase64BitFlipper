from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from java.util import List, ArrayList
import random
import base64
from random import randint

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        return

    def getGeneratorName(self):
        return "Base64 Bit Flipper"

    def createNewInstance(self, attack):
        return B64BitFlipper(self, attack)

class B64BitFlipper(IIntruderPayloadGenerator):
    MODE_RAND = 0 # Replaces a random byte with a random value on each iteration 
    MODE_ITER = 1 # Iterates through each byte and possible value
    MODE_ITER_RAND = 2 # Iterates through each byte and replaces it with a random value

    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.payload_length = 1 # This will get reset by getNextPayload
        self.max_bytes = 16 # Number of bytes to try replacements on
        self.max_values = 16 # Number of values to try for each byte
        self.current_pos = 1
        self.current_value = 0
        self.mode = self.MODE_ITER;
        return

    def hasMorePayloads(self):
        if (self.current_pos <= self.payload_length) and (self.current_pos <= self.max_bytes):
            return True
        else:
            return False

    def getNextPayload(self,current_payload):
        payload = self._helpers.base64Decode(current_payload)
        self.payload_length = len(payload) 
        
        if (self.mode == self.MODE_ITER):
            payload.pop(self.current_pos)
            payload.insert(self.current_pos, self.current_value)
        if (self.mode == self.MODE_ITER_RAND):
            payload.pop(self.current_pos)
            payload.insert(self.current_pos, randint(0,255))
        elif (self.mode == self.MODE_RAND):
            rand_pos = randint(0, len(payload)-1)
            payload.pop(rand_pos)
            payload.insert(rand_pos, randint(0,255))
        
        self.current_value += 1
        if self.current_value >= self.max_values:
            self.current_pos += 1 
            self.current_value = 0
        
        return self._helpers.base64Encode(payload)

    def reset(self):
       self.current_pos = 1
       self.current_value = 0
       return
