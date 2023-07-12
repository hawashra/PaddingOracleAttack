#!/usr/bin/python3
import socket
from binascii import hexlify, unhexlify
import sys

# XOR two bytearrays
def xor(first, second):
    return bytearray(x^y for x,y in zip(first, second))

class PaddingOracle:

    def __init__(self, host, port) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

        ciphertext = self.s.recv(4096).decode().strip()
        self.ctext = unhexlify(ciphertext)

    def decrypt(self, ctext: bytes) -> None:
        self._send(hexlify(ctext))
        return self._recv()

    def _recv(self):
        resp = self.s.recv(4096).decode().strip()
        return resp 

    def _send(self, hexstr: bytes):
        self.s.send(hexstr + b'\n')

    def __del__(self):
        self.s.close()




def find_blocks(port):

    oracle = PaddingOracle('10.9.0.80', port)
    iv_and_ctext = bytearray(oracle.ctext)

    # define a variable that will determine the number of cipher text blocks
    # we will decrypt all the cipher blocks 

    noOfBlocks = (len(iv_and_ctext) - 16) // 16 # number of Ci (cipher blocks)

    print('number of blocks = ', noOfBlocks)
    Plains = []

    xors = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        ,0x10]
    

    D = bytearray(16)
    CC_prev = bytearray(16) # modified C_i-1 for guessing Pi block bytes, first round it is modified IV to get P1

    # decrypt all the cihpertext blocks. 
    for index in range(1, noOfBlocks+1):

        
        C_prev    = iv_and_ctext[16*(index-1):16*index]  # previous cipher block (first round it is IV)
        C_curr    = iv_and_ctext[16*(index):16*(index+1)]  # current cipher we want to attack (decrypt with padding attack)

        print("C_prev:  " + C_prev.hex())
        print("C_curr:  " + C_curr.hex())

        for i in range(16):
            D[i] = C_prev[i]
            CC_prev[i] = 0x00

        # find all 16 bytes of current plain text block 
        for K in range(1, 17):
            
            print(f'finding the bit D2{[16-K]} for P{[index]}')

            if K > 1:
                for j in range(1, K):
                    CC_prev[16-j] = D[16-j] ^ xors[K-1]
            

            for i in range(256):
                CC_prev[16 - K] = i
                status = oracle.decrypt(CC_prev + C_curr)
                if status == "Valid":
                    #print(f"found D2[{16-K}] = ", "0x{:02x}".format(i))
                    print("Valid: i = 0x{:02x}".format(i))
                    print("CC_prev: " + CC_prev.hex())
                    D[16-K] = CC_prev[16-K] ^ xors[K-1]
                
            
        P = xor(D, C_prev)
        Plains.append(P.hex())
    

    return Plains


if __name__ == "__main__":


    port = int(sys.argv[1])


    plains = find_blocks(port)


    for i, plain in enumerate(plains):
        print(f'P[{i+1}] = {plain}')