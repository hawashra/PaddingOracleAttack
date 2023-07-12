#!/usr/bin/python3

import socket

from binascii import hexlify, unhexlify



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





if __name__ == "__main__":

    oracle = PaddingOracle('10.9.0.80', 5000)



    # Get the IV + Ciphertext from the oracle

    iv_and_ctext = bytearray(oracle.ctext)

    IV = iv_and_ctext[:16]

    C1 = iv_and_ctext[16:32]  # 1st block of ciphertext

    C2 = iv_and_ctext[32:48]  # 2nd block of ciphertext

    C3 = iv_and_ctext[48:64]  # 3rd block of ciphertext



    # Initialize an empty plaintext array

    plaintext = bytearray(48)



    # Perform padding oracle attack for each block

    for block_num, C in enumerate([C1, C2, C3], start=1):

        print(f"Block {block_num}:")

        D = bytearray(16)

        P = bytearray(16)



        # Iterate through each byte in the block

        for byte_num in range(15, -1, -1):

            # Construct the modified ciphertext

            CC = bytearray(16)

            padding = 16 - byte_num



            # Set the bytes of D and CC based on the known values

            for i in range(byte_num + 1, 16):

                D[i] = P[i] ^ (byte_num + 1)

                CC[i] = D[i] ^ (byte_num + 1)



            # Try all possible values for the current byte

            for guess in range(256):

                CC[byte_num] = guess



                # Send the modified ciphertext to the oracle

                status = oracle.decrypt(IV + CC + C)



                # Check if the padding is valid

                if status == "Valid":

                    # Update the corresponding bytes of D and CC

                    D[16 - byte_num] = guess ^ byte_num

                    for lol in range(1, 17):
                        CC[lol] = D[lol] ^ (byte_num + 1)



                    # Update the corresponding byte of the plaintext

                    P[16 - byte_num] = IV[16 - byte_num] ^ D[16 - byte_num]



                    print(f"Byte {byte_num}: D = {D.hex()}")



        # Update the IV and C for the next block

        IV = C

        plaintext[(block_num - 1) * 16: block_num * 16] = P



    # Split the plaintext into P1, P2, P3

    P1 = plaintext[:16]

    P2 = plaintext[16:32]

    P3 = plaintext[32:]



    # Print the plaintext blocks

    print("P1:", P1.decode(errors='ignore'))
    print("P2:", P2.decode(errors='ignore'))
    print("P3:", P3.decode(errors='ignore'))