import pathlib
import gen
import argparse
import string

MD5_HASH_LEN = 16
SHA1_HASH_LEN = 20
A = string.ascii_letters + string.digits
A_LEN = len(A)
D = string.digits
D_LEN = len(D)
L = string.ascii_lowercase
L_LEN = len(L)
U = string.ascii_uppercase
U_LEN = len(U)

POSSIBLE_MASK_VAL = ['a', 'd', 'l', 'u']


def crack(args):
    check_m, m_len = check_mask(args.mask)
    if check_m:
        password_cur = [0] * m_len
        hash_func, n1, n2, hash_r = parse_file(args.filename)
        brute(password_cur, hash_func, n1, n2, hash_r, args.mask)
    else:
        print("Incorrect mask parameters!")
        exit(0)


def get_pas_from_arr(pas_arr, mask):
    res = ""
    for i in range(len(mask)):
        res += get_letter_from_alphabet(mask[i], pas_arr[i])
    return res


def gain_hash_func(hash_val):
    if len(hash_val) == (MD5_HASH_LEN * 2):
        return 'md5'
    if len(hash_val) == (SHA1_HASH_LEN * 2):
        return 'sha1'


def check_mask(mask):
    count = 0
    for letter in mask:
        count += 1
        if letter not in POSSIBLE_MASK_VAL:
            return False, 0
    return True, count


def brute(password_cur, algo, n1, n2, hash_r, mask):
    password_next = get_next_pass(password_cur, mask)
    finish = [0] * len(password_cur)
    while True:
        password = get_pas_from_arr(password_cur, mask)
        skeyid = gen.prf(algo, password.encode().hex(), n1)
        hash_r_poss = gen.count_hash_r(algo, skeyid.hex(), n2)
        if hash_r_poss.hex().__eq__(hash_r):
            print('Password recovered! Password  ::  ', password)
            return
        password_cur = password_next
        if password_cur == finish:
            break
        password_next = get_next_pass(password_cur, mask)
    print('Password was not found')


def parse_file(filename):
    with open(filename, 'r') as file:
        text = file.read()
        parameters = text.split('*')
        if len(parameters) == 9:
            n_i = parameters[0]
            n_r = parameters[1]
            g_x = parameters[2]
            g_y = parameters[3]
            c_i = parameters[4]
            c_r = parameters[5]
            sai = parameters[6]
            idr = parameters[7]
            hash_r = parameters[8]
            prf_type = gain_hash_func(hash_r)
            n2 = g_y + g_x + c_r + c_i + sai + idr
            n1 = n_i + n_r
            return prf_type, n1, n2, hash_r
        else:
            raise Exception("Incorrect file!")


def get_letter_from_alphabet(letter, pos):
    if letter == 'a':
        return A[pos]
    if letter == 'l':
        return L[pos]
    if letter == 'u':
        return U[pos]
    if letter == 'd':
        return D[pos]


def get_alph_len(letter):
    if letter == 'a':
        return A_LEN
    if letter == 'l':
        return L_LEN
    if letter == 'u':
        return U_LEN
    if letter == 'd':
        return D_LEN


def get_next_pass(password, mask):
    let = len(password) - 1
    pas = password.copy()
    while let >= 0 and pas[let] == get_alph_len(mask[let]) - 1:
        pas[let] = 0
        let -= 1
    if let >= 0:
        pas[let] += 1
    return pas


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-m',
                        '--mask',
                        action='store',
                        type=str,
                        required=True,
                        help=
                        '''enter mask's value:: 
                            a – letter 
                            d – digit
                            l – small letter 
                            u – big letter''')
    parser.add_argument('-f',
                        '--filename',
                        action='store',
                        type=pathlib.Path,
                        help='file must consist of ')
    crack(parser.parse_args())
