#!/usr/bin/env python3
from petlib.bn import Bn
from hashlib import sha256
from petlib.pack import encode


def get_X_i_list(commitments, n):
    '''
    Calculates all X_i given commitments
    '''
    return [__get_X_i(commitments, i) for i in range(1, n+1)]

def __get_X_i(C_list, i):
    '''
    Calculates one X_i given commitments and index
    '''
    i = Bn(i)
    elements = [(i**j) * C_j for (C_j, j)
                in zip(C_list, range(len(C_list)))]
    ans = elements[0]
    for e in elements[1:]:
        ans = ans + e
    return ans

# Chaum-Pedersen non interactive. Both for single value and list of values.
def DLEQ_prove(params, g_1, g_2, h_1, h_2, x_i):
    '''
    Generate Chaum-Pedersen non interactive proof for one value
    '''
    (_, p, _, _) = params
    w = p.random()
    (a_1, a_2) = __DLEQ_prover_calc_a(g_1, g_2, w)
    c = hash(p, h_1, h_2, a_1, a_2)
    r = __DLEQ_calc_r(p, w, x_i, c)
    return c, r, a_1, a_2


def __DLEQ_prover_calc_a(g_1, g_2, w):
    '''
    Calulates a_1, a_2 as used by prover in proof.
    '''
    a_1 = w * g_1
    a_2 = w * g_2
    return a_1, a_2


def DLEQ_verifyer_calc_a(r, c, g_1, h_1, g_2, h_2):
    '''
    Calculates a_1, a_2 as used by verifyer in verification of correct proof
    '''
    a_1 = r * g_1 + c * h_1
    a_2 = r * g_2 + c * h_2
    return a_1, a_2


def DLEQ_prove_list(p, g, C_list, Y_list, y_list, shares_list):
    '''
    Generate Chaum-Pedersen non interactive proof for a list
    '''
    n = len(Y_list)
    X_list = get_X_i_list(C_list, n)

    assert len(X_list) == len(y_list)
    assert len(Y_list) == len(y_list)
    n = len(X_list)

    w_list = [p.random() for i in range(n)]
    a_1_list = [w_list[i] * g for i in range(n)]
    a_2_list = [w_list[i] * y_list[i] for i in range(n)]

    # Calculates one hash for the entire list
    c = hash(p, X_list, Y_list, a_1_list, a_2_list)
    r_list = __DLEQ_calc_all_r(p, shares_list, w_list, c)

    proof = {'c': c, 'r_list': r_list,
             'a_1_list': a_1_list, 'a_2_list': a_2_list}

    return proof


def hash(p, h_1, h_2, a_1, a_2) -> Bn:
    '''
    Calculates a cryptograpic hash for use in proof. Does work both for DLEQ of single objects and lists.
    '''
    bin_hash = sha256(encode([h_1, h_2, a_1, a_2])).digest()
    return Bn.from_binary(bin_hash)


def __DLEQ_calc_all_r(p, shares_list, w_list, c):
    '''
    Calculates the r values used in list version of DLEQ proof.
    '''
    r_list = [__DLEQ_calc_r(p, w, alpha, c)
              for (alpha, w) in zip(shares_list, w_list)]
    return r_list


def __DLEQ_calc_r(p, w, alpha, c):
    '''
    Calulates a r value for use in both DLEQ single object and list versions.
    '''
    r = (w - c * alpha) % p
    return r


def DLEQ_verify_list(p, g, y_list, C_list, Y_list, proof):
    '''
    Verify that a DLEQ_list proof is correct
    '''
    r_list = proof['r_list']
    c_claimed = proof['c']
    a_1_orig_list = proof['a_1_list']
    a_2_orig_list = proof['a_2_list']

    n = len(r_list)

    X_list = get_X_i_list(C_list, n)
    c = hash(p, X_list, Y_list, a_1_orig_list, a_2_orig_list)
    # If prover lied about c
    if c_claimed != c:
        return False

    for (g_2, h_1, h_2, r_i, a_1, a_2) in zip(y_list, X_list, Y_list, r_list, a_1_orig_list, a_2_orig_list):
        if not DLEQ_verify(g, g_2, h_1, h_2, (c, r_i, a_1, a_2)):
            return False
    return True


def DLEQ_verify_single(p, g_1, g_2, h_1, h_2, proof):
    '''
    Verify that a DLEQ_single proof is correct.
    '''
    (c_claimed, _, a_1, a_2) = proof
    c = hash(p, h_1, h_2, a_1, a_2)
    if c != c_claimed:
        return False
    return DLEQ_verify(g_1, g_2, h_1, h_2, proof)


def DLEQ_verify(g_1, g_2, h_1, h_2, proof):
    '''
    Verify that a participants proof of correct decryption of their share. Assumes c is verified beforehand!
    '''
    (c, r, a_1, a_2) = proof
    (a_1_new, a_2_new) = DLEQ_verifyer_calc_a(r, c, g_1, h_1, g_2, h_2)

    if a_1 == a_1_new and a_2 == a_2_new:
        return True
    return False
