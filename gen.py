import argparse
import hmac

fixed_file = "default.txt"


def protocol(args):
    with open(fixed_file, 'r') as file:
        nonce_1 = file.readline()[5:-1] + file.readline()[5:-1]
        g_x = file.readline()[5:-1]
        g_y = file.readline()[5:-1]
        c_i = file.readline()[5:-1]
        c_r = file.readline()[5:-1]
        sai = file.readline()[5:-1]
        idr = file.readline()[5:-1]
        nonce_2 = g_y+g_x+c_r+c_i+sai+idr
        skeyid = prf(args.hash, args.password.encode().hex(), nonce_1)
        hash_r = count_hash_r(args.hash, skeyid.hex(), nonce_2)
        create_file_write_result(args.password, args.hash, hash_r)


# g_xr, g_xi, c_r, c_i, sa_i, id_r
def count_hash_r(hash_func, skeyid, nonce_hash):
    hash_r = prf(hash_func, skeyid, nonce_hash)
    return hash_r


def create_file_write_result(password, hash_f, hash_r):
    with open(password + "_" + hash_f + ".txt", "w") as file:
        hash_r = hash_r.hex()
        with open(fixed_file, "r") as fix:
            s = fix.readline()
            while s:
                file.write(s[5:-1] + "*")
                s = fix.readline()
        file.write(hash_r)


def prf(hash_func, key, mes):
    if hash_func.__eq__('sha1'):
        return hmac.new(bytes.fromhex(key), bytes.fromhex(mes), "sha1").digest()
    else:
        return hmac.new(bytes.fromhex(key), bytes.fromhex(mes), "md5").digest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p',
                        '--password',
                        action='store',
                        type=str,
                        required=True,
                        help='enter password')
    parser.add_argument('--hash',
                        action='store',
                        type=str,
                        required=True,
                        help='enter the name of hash function',
                        choices=['md5', 'sha1'])
    protocol(parser.parse_args())
