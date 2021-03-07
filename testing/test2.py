"""Tests, examples, and benchmarks"""

import os
import time
from tqdm import tqdm
from core.sharing import *

def speed_benchmark():
    su = SharingUtility("alice", "123")
    size = 32
    data = bytearray(size)
    rand = Random.new()
    res = ""
    for _ in range(1):
        dur_enc = 0
        dur_dec = 0
        times = 50
        for _ in range(times):

            # encryption
            start = time.time()
            iv = rand.read(block_size)
            key = su.key_gen(iv)
            ciphertext = sym_enc(data, key, iv)
            end = time.time()
            dur_enc += (end - start) * 1000

            # decryption
            start = time.time()
            iv = ciphertext[:block_size]
            key = su.key_gen(iv)
            plaintext = sym_dec(ciphertext, key)
            end = time.time()
            dur_dec += (end - start) * 1000

        dur_enc /= times
        dur_dec /= times
        line = f"{size},{dur_enc},{dur_dec}"
        print(line)
        res += line + "\n"
    return res

def keygen_benchmark():
    su = SharingUtility("alice", "123")
    iv = Random.new().read(block_size)
    dur = 0
    times = 100
    for _ in range(times):
        start = time.time()
        key = su.key_gen(iv)
        end = time.time()
        dur += (end - start) * 1000 * 1000
    dur /= times
    print(f"{dur}ns")

def main(args):
    keygen_benchmark()
