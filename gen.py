import argparse
import hmac

fixed_file = "default.txt"


def protocol(args):
    with open(fixed_file, 'r') as file:
        skeyid = prf(args.hash, args.password, file.readline()[5:]+file.readline()[5:])
        print(type(skeyid))
        create_file_write_result(args.password, args.hash, skeyid)


def create_file_write_result(password, hash_f, skeyid):
    with open(password + "_" + hash_f + ".txt", "w") as file:
        skeyid = skeyid.hex()
        with open(fixed_file, "r") as fix:
            s = fix.readline()
            while s:
                file.write(s[5:-1]+"*")
                s = fix.readline()
        file.write(skeyid)


def prf(hash_func, key, mes):
    if hash_func.__eq__('sha1'):
        return hmac.new(key.encode(), mes.encode(), "sha1").digest()
    else:
        return hmac.new(key.encode(), mes.encode(), "md5").digest()


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
