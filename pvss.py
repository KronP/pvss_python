#!/usr/bin/env python3
from typing import Any
from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
from . import cpni

encrypted_share_type = Bn
encrypted_shares_type = list[encrypted_share_type]
commitments_type = list[Bn]
pub_keys_type = list[Bn]
proof_type = dict[str, Any]
share_type = Bn
single_proof_type = dict[str, Bn]
generator_type = EcPt
decrypted_share_type = Bn
decrypted_shares_list_type = list[decrypted_share_type]
index_list_type = list[Bn]


def gen_proof(params, k, n, secret, pub_keys):
    '''
    Generate polynomial and proof
    '''
    assert n > k
    assert len(pub_keys) == n
    (Gq, p, g0, h) = params

    px = gen_polynomial(k, secret, p)
    commitments = get_commitments(h, px)
    shares_list = calc_shares(px, k, n, p)
    enc_shares = __get_encrypted_shares(pub_keys, shares_list)

    pub = {'C_list': commitments, 'Y_list': enc_shares}

    proof = cpni.DLEQ_prove_list(p, h, commitments, enc_shares, pub_keys, shares_list)

    # Debug:
    assert len(px) == k
    assert len(commitments) == k
    assert len(shares_list) == n
    assert shares_list[0] != secret
    assert len(enc_shares) == n

    return pub, proof


def gen_polynomial(k: int, secret: Bn, p) -> list[Bn]:
    '''
    Generate polynomial
    '''
    px_rand = [p.random() for i in range(k-1)]
    px = [secret] + px_rand
    return px


def calc_shares(px: list[Bn], k: int, n: int, p: Bn):
    '''
    Calculates p(j) for all j (0,n)
    '''
    return [__calc_share(px, k, Bn(i), p) for i in range(1, n + 1)]


def __calc_share(px: list[Bn], k: int, x: Bn, p: Bn):
    '''
    Calculates p(x)
    '''
    assert len(px) == k
    result = 0
    for (alpha, j) in zip(px, range(k)):
        result = (result + alpha * (x**j)) % p
    return result


def get_commitments(h, px):
    '''
    Calculates all commitments C_j for j =[0,k)
    '''
    return [p_i * h for p_i in px]


def __get_encrypted_shares(pub_keys: pub_keys_type, shares: list[share_type]) -> encrypted_shares_type:
    '''
    Calculates the encrypted shares Y_i for all i in (1,n)
    '''
    assert len(pub_keys) == len(shares)
    Y_i_list = [(shares[i]) * y_i for (y_i, i)
                in zip(pub_keys, range(len(pub_keys)))]
    return Y_i_list


def decode(S_list, index_list, p):
    '''
    Calculates secret from participants decrypted shares
    '''
    assert len(S_list) == len(index_list)

    ans = __lagrange(index_list[0], index_list, p) * S_list[0]
    for (S_i, i) in zip(S_list[1:], range(1, len(S_list))):
        ans = ans + __lagrange(index_list[i], index_list, p) * S_i
    return ans


def __lagrange(i, index_list, p):
    '''
    Calculate lagrange coefficient
    '''
    top = Bn(1)
    bottom = Bn(1)
    for j in index_list:
        if j != i:
            top = (top * j)
            bottom = (bottom * (j-i))
    return top.mod_mul(bottom.mod_inverse(p), p)


def verify_correct_decryption(S_i, Y_i, decrypt_proof, pub_key, p, G):
    '''
    Verifies the participants proof of correct decryption of their share
    '''
    return cpni.DLEQ_verify_single(p, G, S_i, pub_key, Y_i, decrypt_proof)


def batch_verify_correct_decryption(proved_decryptions, Y_list, pub_keys, p, G):
    '''
    Verify all participants decryption of shares
    '''
    for ((S_i, decrypt_proof), Y_i, pub_key) in zip(proved_decryptions, Y_list, pub_keys):
        if verify_correct_decryption(S_i, Y_i, decrypt_proof, pub_key, p, G) is False:
            return False
    return True


def helper_generate_key_pair(params):
    '''
    Generates a key-pair, returns both the private key and the public key
    '''
    (_, p, g0, g1) = params
    x_i = p.random()
    y_i = x_i * g0
    return (x_i, y_i)


def participant_decrypt(params, x_i, Y_i):
    '''
    Decrypt a encrypted share with stored private key
    '''
    (_, p, _, _) = params
    return x_i.mod_inverse(p) * Y_i


def participant_decrypt_and_prove(params, x_i, Y_i) -> tuple[decrypted_share_type, single_proof_type]:
    '''
    Decrypts a encrypted share with stored private key, and generates proof of it being done correctly.
    '''
    (_, p, g0, _) = params
    S_i = participant_decrypt(params, x_i, Y_i)

    y_i = x_i * g0

    decrypt_proof = cpni.DLEQ_prove(params, g0, S_i, y_i, Y_i, x_i)
    return S_i, decrypt_proof


def get_pub_key(params, x_i):
    '''
    Returns the public key
    '''
    (_, _, g0, G) = params
    y_i = x_i * g0
    return y_i
