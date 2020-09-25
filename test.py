import time
from tqdm import tqdm
from sharing import *

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

def tables_size_test():
    print("* Tables storage cost")

    print("** RUNNING N VS COST")
    U = 1

    aw = FakeAccessWrapper(use_json=False)
    alice = SharingUtility("alice", "abc", access_wrapper=aw)

    bobs = [None] * U
    for u in range(len(bobs)):
        bobs[u] = SharingUtility(f"U_{u}", "123", access_wrapper=aw)

    res = ""
    for N in tqdm(range(1, 101)):
        # 16 bytes = 32 bytes hex str = 256 bits file name
        f = secrets.token_bytes(16).hex()
        aw.fake_file(alice, f, size=4) # keep it tiny
        for bob in bobs:
            alice.share_file(f, bob.user_id, bob.keys["pub"])
        res += f"{N},{aw.storage_cost()}\n"

    with open("./tmp/sharing_test/test_sharing_N_vs_cost.csv", "w") as f:
        f.write(res)

    print("** RUNNING U VS COST")
    N = 1

    # to save time of key generation
    alice = SharingUtility("alice", "abc", access_wrapper=aw)
    bob = SharingUtility(f"bob", "123", access_wrapper=aw)

    res = ""
    for U in tqdm(range(1, 101)):
        aw = FakeAccessWrapper(use_json=False)
        f = secrets.token_bytes(16).hex()
        aw.fake_file(alice, f, size=4)

        alice = SharingUtility("alice", None, alice.keys["sym"], alice.keys["pub"], alice.keys["priv"], access_wrapper=aw)

        bobs = [None] * U
        for u in range(len(bobs)):
            bobs[u] = SharingUtility(f"U_{u}", None, bob.keys["sym"], bob.keys["pub"], bob.keys["priv"], access_wrapper=aw)
            alice.share_file(f, bobs[u].user_id, bobs[u].keys["pub"])

        res += f"{U},{aw.storage_cost()}\n"

    with open("./tmp/sharing_test/test_sharing_U_vs_cost.csv", "w") as f:
        f.write(res)

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

    print("** Revoking Bob from accessing foo.txt (by Alice)")
    ret = alice.revoke_shared_file("foo.txt", bob.user_id, bob.keys["pub"])
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

def aes_test():
    print("* AES test")
    print("building keys...")
    t = time.time()
    keys = gen_keys_from("passs")
    print(f"done {time.time() - t}")
    msg = b"hellooooo"
    print(f"encrypting...")
    print(f"msg = {msg}")
    t = time.time()
    enc = AES_enc(msg, keys["sym"])
    print(f"done {time.time() - t}")
    print(f"enc = {enc.hex()}")
    print("decrypting")
    t = time.time()
    dec = AES_dec(enc, keys["sym"])
    print(f"done {time.time() - t}")
    print(f"dec = {dec}")

def rsa_test():
    print("* RSA test")
    print("building keys...")
    t = time.time()
    keys = gen_keys_from("passs")
    print(f"done {time.time() - t}")
    msg = b"hellooooo"
    print(f"encrypting...")
    print(f"msg = {msg}")
    t = time.time()
    enc = RSA_enc(msg, keys["pub"])
    print(f"done {time.time() - t}")
    print(f"enc = {enc.hex()}")
    print("decrypting")
    t = time.time()
    dec = RSA_dec(enc, keys["priv"])
    print(f"done {time.time() - t}")
    print(f"dec = {dec}")

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

if __name__ == "__main__":
    #tables_json_vs_pickle()
    #tables_test()
    #sharing_test()
    #tables_size_test()
    #aes_test()
    #rsa_test()
    #keys_test()
    keys_caching_test()
