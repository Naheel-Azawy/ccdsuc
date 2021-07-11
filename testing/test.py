"""Tests, examples, and benchmarks"""

import os
import time
from tqdm import tqdm
from core.sharing import *

# returns a csv string with "file_size,time_to_encrypt"
def speed_benchmark_helper(sharing):
    if sharing:
        su = SharingUtility("alice", "123")
    else:
        fixed_key = secrets.token_bytes(nbytes=int(AES.key_size[-1]))
    res = ""
    for size in tqdm(range(0, 10000000, 50000)):
    #for size in range(1):
        dur_enc = 0
        dur_dec = 0
        times = 10
        for _ in range(times):
            iv = Random.new().read(block_size)
            data = bytearray(size)

            # encryption
            start = time.time()
            if sharing:
                key = su.key_gen(iv)
            else:
                key = fixed_key
            ciphertext = sym_enc(data, key, iv)
            end = time.time()
            dur_enc += (end - start) * 1000

            # decryption
            start = time.time()
            if sharing:
                iv = ciphertext[:block_size]
                key = su.key_gen(iv)
            else:
                key = fixed_key
            plaintext = sym_dec(ciphertext, key)
            end = time.time()
            dur_dec += (end - start) * 1000

        dur_enc /= times
        dur_dec /= times
        res += f"{size},{dur_enc},{dur_dec}\n"
    return res

def speed_benchmark():
    print("* Encryption/decryption speed benchmark")

    print("** RUNNING SHARING TEST")
    p = "./testing/benchmarks/test_sharing_speed.csv"
    if not os.path.exists(p):
        with open(p, "w") as f:
            f.write(speed_benchmark_helper(True))
    else:
        print(f"{p} already exist")

    print("** RUNNING NO SHARING TEST")
    p = "./testing/benchmarks/test_no_sharing_speed.csv"
    if not os.path.exists(p):
        with open(p, "w") as f:
            f.write(speed_benchmark_helper(False))
    else:
        print(f"{p} already exist")

def tables_size_benchmark():
    print("* Tables storage cost benchmark")

    print("** RUNNING N VS COST")
    p = "./testing/benchmarks/test_sharing_N_vs_cost.csv"
    if os.path.exists(p):
        print(f"{p} already exist")
    else:
        U = 1

        aw = FakeAccessWrapper(use_json=False)
        alice = SharingUtility("alice", "abc", access_wrapper=aw)

        bobs = [None] * U
        for u in range(len(bobs)):
            bobs[u] = SharingUtility(f"B{u:03}", "123", access_wrapper=aw)

        res = ""
        for N in tqdm(range(0, 101)):
            # 16 bytes = 32 bytes hex str = 256 bits file name
            f = secrets.token_bytes(16).hex()
            aw.fake_file(alice, f, size=4) # keep it tiny
            for bob in bobs:
                alice.share_file(f, bob.user_id, bob.keys["pub"])
            full_size = aw.storage_size()
            overhead = aw.storage_cost()
            percent = (overhead / full_size) * 100
            res += f"{N},{overhead},{full_size},{percent}\n"

        with open(p, "w") as f:
            f.write(res)

    print("** RUNNING U VS COST")
    p = "./testing/benchmarks/test_sharing_U_vs_cost.csv"
    if os.path.exists(p):
        print(f"{p} already exist")
    else:
        N = 1

        # to save time of key generation
        alice = SharingUtility("alice", "abc", access_wrapper=aw)
        bob = SharingUtility(f"bob", "123", access_wrapper=aw)

        res = ""
        for U in tqdm(range(0, 101)):
            aw = FakeAccessWrapper(use_json=False)
            f = secrets.token_bytes(16).hex()
            aw.fake_file(alice, f, size=4)

            alice = SharingUtility("alice", None, alice.keys["sym"], alice.keys["pub"], alice.keys["priv"], access_wrapper=aw)

            bobs = [None] * U
            for u in range(len(bobs)):
                bobs[u] = SharingUtility(f"B{u:03}", None, bob.keys["sym"], bob.keys["pub"], bob.keys["priv"], access_wrapper=aw)
                alice.share_file(f, bobs[u].user_id, bobs[u].keys["pub"])

            full_size = aw.storage_size()
            overhead = aw.storage_cost()
            percent = (overhead / full_size) * 100
            res += f"{U},{overhead},{full_size},{percent}\n"

        with open(p, "w") as f:
            f.write(res)

def tables_size_3d_benchmark():
    print("* Storage overhead cost benchmark")

    p = "./testing/benchmarks/test_sharing_cost_overhead.csv"
    if os.path.exists(p):
        print(f"{p} already exist")
    else:
        # to save time of key generation
        alice = SharingUtility("alice", "abc")
        bob = SharingUtility(f"bob", "123")

        res = ""

        step = 10
        for y in tqdm(range(0, 101, step)):
            for x in tqdm(range(0, 101, step)):
                aw = FakeAccessWrapper(use_json=False)

                alice = SharingUtility("alice", None,      \
                                       alice.keys["sym"],  \
                                       alice.keys["pub"],  \
                                       alice.keys["priv"], \
                                       access_wrapper=aw)

                files = [None] * x
                bobs  = [None] * y

                for f in range(len(files)):
                    # 16 bytes = 32 bytes hex str = 256 bits file name
                    files[f] = secrets.token_bytes(16).hex()
                    aw.fake_file(alice, files[f], size=4) # keep it tiny

                for u in range(len(bobs)):
                    bobs[u] = SharingUtility(f"B{u:03}", None, \
                                             bob.keys["sym"],  \
                                             bob.keys["pub"],  \
                                             bob.keys["priv"], \
                                             access_wrapper=aw)

                for u in range(len(bobs)):
                    for f in range(len(files)):
                        alice.share_file(files[f], bobs[u].user_id, bobs[u].keys["pub"])

                o = aw.storage_cost()
                res += f"{x},{y},{o}\n"

        with open(p, "w") as f:
            f.write(res)

def overhead_percent_benchmark():
    print("* Overhead percent vs files sizes")

    p = "./testing/benchmarks/test_overhead_percent.csv"
    if os.path.exists(p):
        print(f"{p} already exist")
    else:
        x = 10
        y = 10
        aw = FakeAccessWrapper(use_json=False)
        alice = SharingUtility("alice", "abc", access_wrapper=aw)

        U = y
        bobs = [None] * U
        for u in range(len(bobs)):
            bobs[u] = SharingUtility(f"B{u:03}", "123", access_wrapper=aw)

        res = ""
        for fsize in tqdm(range(0, 512 * 1024, 4096)):

            for N in range(0, x):
                # 16 bytes = 32 bytes hex str = 256 bits file name
                f = secrets.token_bytes(16).hex()
                aw.fake_file(alice, f, size=fsize)
                for bob in bobs:
                    alice.share_file(f, bob.user_id, bob.keys["pub"])
                full_size = aw.storage_size()

            overhead = aw.storage_cost()
            percent = (overhead / full_size) * 100
            res += f"{fsize},{overhead},{full_size},{percent}\n"
            aw.cleanup()

        with open(p, "w") as f:
            f.write(res)

def tables_size_benchmark_foo():
    print("* Tables storage cost benchmark")

    print("** RUNNING N VS COST")
    p = "./testing/benchmarks/test_sharing_N_vs_cost.csv"
    if os.path.exists(p):
        print(f"{p} already exist")
    else:
        U = 1

        aw = FakeAccessWrapper(use_json=False)
        alice = SharingUtility("alice", "abc", access_wrapper=aw)

        bobs = [None] * U
        for u in range(len(bobs)):
            bobs[u] = SharingUtility(f"B{u:03}", "123", access_wrapper=aw)

        res = ""
        for N in tqdm(range(1, 101)):
            # 16 bytes = 32 bytes hex str = 256 bits file name
            f = secrets.token_bytes(16).hex()
            aw.fake_file(alice, f, size=4) # keep it tiny
            for bob in bobs:
                alice.share_file(f, bob.user_id, bob.keys["pub"])
            res += f"{N},{aw.storage_cost()}\n"

        with open(p, "w") as f:
            f.write(res)

    print("** RUNNING U VS COST")
    p = "./testing/benchmarks/test_sharing_U_vs_cost.csv"
    if os.path.exists(p):
        print(f"{p} already exist")
    else:
        N = 1

        # to save time of key generation
        alice = SharingUtility("alice", "abc", access_wrapper=aw)
        bob = SharingUtility(f"bob", "123", access_wrapper=aw)

        res = ""
        for U in tqdm(range(1, 2)):
            aw = FakeAccessWrapper(use_json=True)
            f = secrets.token_bytes(16).hex()
            aw.fake_file(alice, f, size=4)

            alice = SharingUtility("alice", None, alice.keys["sym"], alice.keys["pub"], alice.keys["priv"], access_wrapper=aw)

            bobs = [None] * U
            for u in range(len(bobs)):
                bobs[u] = SharingUtility(f"B{u:03}", None, bob.keys["sym"], bob.keys["pub"], bob.keys["priv"], access_wrapper=aw)
                print(f">>> sharing with {bobs[u].user_id}...")
                alice.share_file(f, bobs[u].user_id, bobs[u].keys["pub"])

            print(f">>> shared with {U} users")
            for t in aw.tables:
                b = t.split("_")[-1]
                if b == "others":
                    b = alice
                    t_dec = alice.load_table()
                else:
                    b = int(b[1:])
                    b = bobs[b]
                    t_dec = b.load_table("alice")
                t_s = aw.serialize(t_dec)
                if b == alice:
                    t_enc = sym_enc(t_s, alice.keys["sym"])
                else:
                    t_enc = asym_enc_v(t_s, b.keys["pub"])
                print(f"{t}: {len(aw.tables[t])}, {len(t_s)}, {len(t_enc)}, b: {b.user_id}")
                print(t_dec)
                print(t_s)
                print()
            print(f"cost = {aw.storage_cost()}")
            print("======================================")
            res += f"{U},{aw.storage_cost()}\n"

        with open(p, "w") as f:
            f.write(res)

def revocation_benchmark():
    print("* Revocation benchmark")

    print("** RUNNING N VS TIME")
    p = "./testing/benchmarks/test_sharing_revocation_speed_vs_size.csv"
    if not os.path.exists(p):
        aw = FakeAccessWrapper()
        alice = SharingUtility("alice", "abc", access_wrapper=aw)
        bob = SharingUtility("bob", "123", access_wrapper=aw)

        def keys_getter(user):
            if user == bob.user_id: return bob.keys["pub"]
            else: raise Exception(f"Unknown user {user}")

        res = ""
        for size in tqdm(range(1, 1510000, 30000)):
            dur = 0
            times = 10
            for t in range(times):
                fname = f"{size}{t}.txt"
                f_data, f_data_enc = aw.fake_file(alice, fname, size=size)
                alice.share_file(fname, bob.user_id, bob.keys["pub"])
                start = time.time()
                ret = alice.revoke_shared_file(fname, bob.user_id, keys_getter)
                end = time.time()
                dur += (end - start) * 1000
            dur /= times
            res += f"{size},{dur}\n"

        with open(p, "w") as f:
            f.write(res)
    else:
        print(f"{p} already exist")

    print("** RUNNING U VS TIME")
    p = "./testing/benchmarks/test_sharing_revocation_speed_vs_U.csv"
    if not os.path.exists(p):

        # all will have the same keys, just for simplicity of testing
        fake = SharingUtility("fake", "123")
        def keys_getter(user):
            return fake.keys["pub"]

        res = ""
        for u in tqdm(range(1, 101, 2)):
            dur = 0
            times = 5
            for t in range(times):
                # creating the environment
                aw = FakeAccessWrapper()
                #aw.upload_delay = 0
                alice = SharingUtility("alice", "abc", access_wrapper=aw,
                                     k_sym=fake.keys["sym"],
                                     k_pub=fake.keys["pub"],
                                     k_priv=fake.keys["priv"])
                # the file
                fname = "foo.txt"
                f_data, f_data_enc = aw.fake_file(alice, fname, data=b"hello")
                # bobs
                bob = None
                for user in range(u):
                    bob = SharingUtility(f"U{user}", access_wrapper=aw,
                                         k_sym=fake.keys["sym"],
                                         k_pub=fake.keys["pub"],
                                         k_priv=fake.keys["priv"])
                    alice.share_file(fname, bob.user_id, bob.keys["pub"]) # share
                # print(alice.list_files_shared_by_us())
                # print()
                start = time.time()
                ret = alice.revoke_shared_file(fname, bob.user_id, keys_getter)
                end = time.time()
                dur += (end - start) * 1000
            dur /= times
            res += f"{u},{dur}\n"

        with open(p, "w") as f:
            f.write(res)
    else:
        print(f"{p} already exist")

def tables_json_vs_pickle():
    print("* Tables json vs pickle")

    res = {"json": [], "pickle": []}
    for js in [True, False]:
        arr = res["json" if js else "pickle"]
        aw = FakeAccessWrapper(use_json=js)
        alice = SharingUtility("alice", "abc", access_wrapper=aw)
        bob = SharingUtility(f"bob", "123", access_wrapper=aw)

        for N in range(1, 101):
            # 16 bytes = 32 bytes hex str = 256 bits file name
            f = secrets.token_bytes(16).hex()
            aw.fake_file(alice, f, size=4) # keep it tiny
            alice.share_file(f, bob.user_id, bob.keys["pub"])
            arr.append(aw.storage_cost())

    diffs = []
    for i in range(len(res["json"])):
        a, b = res['json'][i], res['pickle'][i]
        diff = ((a - b) / ((a + b) / 2)) * 100
        diffs.append(diff)
        #print(f"json: {a}, pickle: {b}, diff: {diff}")

    print(sum(diffs) / len(diffs), "%")

def tables_test():
    print("* Tables test")

    aw = FakeAccessWrapper(use_json=True)

    alice = SharingUtility("alice", "abc",   access_wrapper=aw)
    bob   = SharingUtility("bob",   "123",   access_wrapper=aw)
    carol = SharingUtility("carol", "12345", access_wrapper=aw)

    def shr(f, fr, to):
        aw.fake_file(alice, f)
        T_A_B, _, T_A_others, _ = \
            fr.share_file(f, to.user_id, to.keys["pub"])
        print(f"T_{fr.user_id}_{to.user_id} = {T_A_B}")
        print(f"T_{fr.user_id}_others = {T_A_others}")
        print("")

    #    file                  from   to
    shr("foo.txt",             alice, bob)
    shr("bar.txt",             alice, bob)
    shr("abc.txt",             alice, bob)
    shr("123.txt",             alice, carol)
    shr("the_thing.txt",       bob,   alice)
    shr("the_other_thing.txt", bob,   alice)
    shr("lots_of_things.txt",  carol, alice)

    print("Files shared with Alice:")
    print(alice.list_files_shared_with_us())
    print("")

def sharing_test():
    print("* Sharing test")
    aw = FakeAccessWrapper()

    alice = SharingUtility("alice", "abc", access_wrapper=aw)
    bob = SharingUtility(f"bob", "123", access_wrapper=aw)

    f_data, f_data_enc = aw.fake_file(alice, "foo.txt")

    print("** Sharing file foo.txt by Alice to Bob")
    alice.share_file("foo.txt", bob.user_id, bob.keys["pub"])

    print("** Files shared by Alice:")
    print(alice.list_files_shared_by_us())

    print("** Files shared with Bob:")
    print(bob.list_files_shared_with_us())

    print("** Loading foo.txt by Bob")
    f_shared_data = aw.load_fake_shared_file(bob, "foo.txt")
    print("** Loaded equals original:")
    print(f_shared_data == f_data)

    print()

    def keys_getter(user):
        if user == bob.user_id:
            return bob.keys["pub"]
        else:
            raise Exception(f"Unknown user {user}")

    print("** Revoking Bob from accessing foo.txt (by Alice)")
    ret = alice.revoke_shared_file("foo.txt", bob.user_id, keys_getter)
    print(f"** Revoke is {ret}")

    print("** Files shared by Alice:")
    print(alice.list_files_shared_by_us())

    print("** Files shared with Bob:")
    print(bob.list_files_shared_with_us())

    print("** Loading foo.txt by Bob")
    f_shared_data = aw.load_fake_shared_file(bob, "foo.txt")
    print("** Loaded equals original:")
    print(f_shared_data == f_data)
    print("** Loaded foo.txt = " + str(f_shared_data))

def sym_test():
    print("* Symmetric crypto test")
    print("building keys...")
    t = time.time()
    keys = gen_keys_from("passs")
    print(f"done {time.time() - t}")
    msg = b"hellooooo"
    print(f"encrypting...")
    print(f"msg = {msg}")
    t = time.time()
    enc = sym_enc(msg, keys["sym"])
    print(f"done {time.time() - t}")
    print(f"enc = {enc.hex()}")
    print("decrypting")
    t = time.time()
    dec = sym_dec(enc, keys["sym"])
    print(f"done {time.time() - t}")
    print(f"dec = {dec}")

def asym_test():
    print("* Asymmetric crypto test")
    print("building keys...")
    t = time.time()
    keys = gen_keys_from("passs")
    print(f"done {time.time() - t}")
    msg = b"hellooooo"
    print(f"encrypting...")
    print(f"msg = {msg}")
    t = time.time()
    enc = asym_enc(msg, keys["pub"])
    print(f"done {time.time() - t}")
    print(f"enc = {enc.hex()}")
    print("decrypting")
    t = time.time()
    dec = asym_dec(enc, keys["priv"])
    print(f"done {time.time() - t}")
    print(f"dec = {dec}")

def simple_keys_test():
    keys = stringify_keys(gen_keys_from("123"))
    print(keys["pub"])

def keys_test():
    keys = gen_keys_from("passs")
    print(keys)
    print("")
    str_keys = stringify_keys(keys)
    print(str_keys)
    print("")
    rev_keys = unstringify_keys(str_keys)
    print(rev_keys)

def keys_caching_test():
    su = SharingUtility("alice", "abc", keys_cache="./keys-test.json")

def pki_test():
    from public_key.pki_bc import BCPKI
    from core.sharing import PublicKey
    pki = BCPKI()
    pki.init()
    print("* Ceritificates before")
    print(pki.list_ids())
    print()

    print("* Adding the device...")
    pki.enroll("led-0", "deadbeef", "2077-01-01")
    print()

    print("* Ceritificates after")
    print(pki.list_ids())
    print()

    print("* Getting the device key...")
    key = pki.get_key("led-0").export_key("PEM").decode()
    print(key)
    print()

    print("* Re-generating keys...")
    new_key = stringify_keys(gen_keys_from("deadbeef"))["pub"]
    print(new_key)

    print("* Key is matching?")
    print(new_key == key)

def server_test():
    import threading
    from iot.tcp_client import Server

    threading.Thread(target=lambda: os.system("python3 ./main.py iot-server")) \
             .start()
    s = Server("127.0.0.1", 2010)
    t = "foo.txt"
    c = b"123 abc"
    print(f"Setting {t} to {c}...")
    print(s.set(t, c))
    print(f"Getting {t}...")
    got = s.get(t)
    print(got)
    print(f"Content {c} of {t} is equivalent:")
    print(c == got)

def reupload_test():
    aw = FakeAccessWrapper()
    alice = SharingUtility("alice", "abc", access_wrapper=aw)

    print("** Creating fake file")
    f_data, f_data_enc = aw.fake_file(alice, "foo", size=4)
    print(f_data)
    print(f_data_enc)

    print("** Decrypting it")
    iv = aw.load_file_iv("foo")
    key = alice.key_gen(iv)
    data = sym_dec(f_data_enc, key) # decrypt
    print(data)

    print("** Re-uploading")
    reuploaded = aw.reupload_file(alice, "foo")
    print(reuploaded)
    f_loaded = aw.load_fake_file("foo")
    print(f_loaded)

    print("** Decrypting it")
    iv = aw.load_file_iv("foo")
    key = alice.key_gen(iv)
    data = sym_dec(f_loaded, key) # decrypt
    print(data)

def revocation_test():
    print("* Revocation test")
    aw = FakeAccessWrapper()

    alice = SharingUtility("alice", "abc", access_wrapper=aw)
    bob1 = SharingUtility(f"bob1", "123", access_wrapper=aw)
    bob2 = SharingUtility(f"bob2", "456", access_wrapper=aw)

    f_data, f_data_enc = aw.fake_file(alice, "foo.txt", data=b"hello")

    print("** Sharing file foo.txt by Alice to Bob1 and Bob2")
    alice.share_file("foo.txt", bob1.user_id, bob1.keys["pub"])
    alice.share_file("foo.txt", bob2.user_id, bob2.keys["pub"])

    print("** Files shared by Alice:")
    print(alice.list_files_shared_by_us())

    print("** Files shared with Bobs:")
    print(bob1.list_files_shared_with_us())
    print(bob2.list_files_shared_with_us())

    print("** Loading foo.txt by Bob1")
    f_shared_data = aw.load_fake_shared_file(bob1, "foo.txt")
    print("** Loaded equals original:")
    print(f_shared_data == f_data)

    print()

    print("** Revoking Bob1 from accessing foo.txt (by Alice)")
    def keys_getter(user):
        if user == bob1.user_id:
            return bob1.keys["pub"]
        elif user == bob2.user_id:
            return bob2.keys["pub"]
        else:
            raise Exception(f"Unknown user {user}")
    ret = alice.revoke_shared_file("foo.txt", bob1.user_id, keys_getter)
    print(f"** Revoke is {ret}")

    print("** Files shared by Alice:")
    print(alice.list_files_shared_by_us())

    print("** Files shared with Bobs:")
    print(bob1.list_files_shared_with_us())
    print(bob2.list_files_shared_with_us())

    print()

    print("** Loading foo.txt by Bob1")
    f_shared_data = aw.load_fake_shared_file(bob1, "foo.txt")
    print("** Loaded equals original:")
    print(f_shared_data == f_data)
    print("** Loaded foo.txt = " + str(f_shared_data))

    print()

    print("** Loading foo.txt by Bob2")
    f_shared_data = aw.load_fake_shared_file(bob2, "foo.txt")
    print("** Loaded equals original:")
    print(f_shared_data == f_data)
    print("** Loaded foo.txt = " + str(f_shared_data))

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
    if len(args) > 1 and args[1] == "benchmark":
        out = "./testing/benchmarks"
        if len(args) > 2 and args[2] == "clean":
            os.system(f"rm -rf {out}")
            return
        if not os.path.isdir(out):
            os.mkdir(out)
        speed_benchmark()
        tables_size_benchmark()
        revocation_benchmark()
        tables_size_benchmark_foo()
        overhead_percent_benchmark()
        tables_size_3d_benchmark()
        return
    tables_json_vs_pickle()
    #tables_test()
    #sharing_test()
    #sym_test()
    #asym_test()
    #keys_test()
    #keys_caching_test()
    #pki_test()
    #simple_keys_test()
    #server_test()
    #reupload_test()
    #revocation_test()
    #keygen_benchmark()
