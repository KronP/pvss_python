#!/usr/bin/env python3
from petlib.ec import EcGroup
import pvss_python.pvss as pvss
import pvss_python.cpni as cpni
import itertools
import pytest


class TestPvss():
    def test_full(self):
        # Generate parameters (should be same in other parts of program)
        Gq = EcGroup()
        p = Gq.order()
        h = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, G, h)

        # Decide on a secret to be distributed
        m = p.from_binary(b'This is a test')

        # Set (t,n)-threshold parameters
        n = 4
        t = 3

        # Initiate participants, and generate their key-pairs
        priv_keys = []
        pub_keys = []
        for i in range(n):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        # Encrypt secret, create shares and proof
        (pub, proof) = pvss.gen_proof(params, t, n, m, pub_keys)

        # Prove generates shares validity
        print("Test verify")
        Y_list = pub['Y_list']
        C_list = pub['C_list']
        assert cpni.DLEQ_verify_list(p, h, pub_keys, C_list, Y_list, proof) is True

        # Decryption
        # Calculate what a correct decryption should be
        expected_decryption = m * G

        # Let participants decrypt their shares and generate proofs
        proved_decryptions = [pvss.participant_decrypt_and_prove(params, x_i, enc_share) for (x_i, enc_share) in zip(priv_keys, pub['Y_list'])]

        # Check participants proofs
        if pvss.batch_verify_correct_decryption(proved_decryptions, pub['Y_list'], pub_keys, p, G) is False:
            print("Verification of decryption failed")

        # Use participants decrypted shares to recreate secret
        S_list = [S_i for (S_i, decrypt_proof) in proved_decryptions]
        actual_decryption = pvss.decode(S_list[0:-1], [1, 2, 3], p)

        # Verify secret
        print("Test decrypt")
        assert expected_decryption == actual_decryption

    def test_edge_case(self):
        # Generate parameters (should be same in other parts of program)
        Gq = EcGroup()
        p = Gq.order()
        h = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, G, h)

        # Decide on a secret to be distributed
        m = p-1

        # Set (t,n)-threshold parameters
        n = 4
        t = 3

        # Initiate participants, and generate their key-pairs
        priv_keys = []
        pub_keys = []
        for i in range(n):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        # Encrypt secret, create shares and proof
        (pub, proof) = pvss.gen_proof(params, t, n, m, pub_keys)

        # Prove generates shares validity
        print("Test verify")
        Y_list = pub['Y_list']
        C_list = pub['C_list']
        assert cpni.DLEQ_verify_list(p, h, pub_keys, C_list, Y_list, proof) is True

        # Decryption
        # Calculate what a correct decryption should be
        expected_decryption = m * G

        # Let participants decrypt their shares and generate proofs
        proved_decryptions = [pvss.participant_decrypt_and_prove(params, x_i, enc_share) for (x_i, enc_share) in zip(priv_keys, pub['Y_list'])]

        # Check participants proofs
        if pvss.batch_verify_correct_decryption(proved_decryptions, pub['Y_list'], pub_keys, p, G) is False:
            print("Verification of decryption failed")

        # Use participants decrypted shares to recreate secret
        S_list = [S_i for (S_i, decrypt_proof) in proved_decryptions]
        actual_decryption = pvss.decode(S_list[0:-1], range(1, 4), p)

        # Verify secret
        print("Test decrypt")
        assert expected_decryption == actual_decryption

    def helper_function_reconstruct(self, t, n):
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        G = Gq.hash_to_point(b'G')
        params = (Gq, p, g, G)

        # Decide on a secret to be distributed
        m = p.from_binary(b'This is a test')

        # Initiate participants, and generate their key-pairs
        priv_keys = []
        pub_keys = []
        for i in range(n):
            (x_i, y_i) = pvss.helper_generate_key_pair(params)
            priv_keys.append(x_i)
            pub_keys.append(y_i)

        # Encrypt secret, create shares and proof
        (pub, proof) = pvss.gen_proof(params, t, n, m, pub_keys)

        # Decryption
        # Calculate what a correct decryption should be
        expected_decryption = m * g

        # Let participants decrypt their shares and generate proofs
        proved_decryptions = [pvss.participant_decrypt_and_prove(params, x_i, enc_share) for (x_i, enc_share) in zip(priv_keys, pub['Y_list'])]
        if pvss.batch_verify_correct_decryption(proved_decryptions, pub['Y_list'], pub_keys, p, G) is False:
            print("Verification of decryption failed")
        S_list = [S_i for (S_i, decrypt_proof) in proved_decryptions]
        return (expected_decryption, S_list, p)

    def helper_function_reconstuct_and_test(self, t, n, index_list):
        (expected_decryption, S_list, p) = self.helper_function_reconstruct(t, n)

        new_S_list = [S_list[index_list[0]-1], S_list[index_list[1]-1], S_list[index_list[2]-1]]
        actual_decryption2 = pvss.decode(new_S_list, index_list, p)

        assert expected_decryption == actual_decryption2

    def test_another_reconstuction(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [2, 3, 4])
    
    def test_1_4_2(self):
        # Set (t,n)-threshold parameters
        n = 4
        t = 3
        self.helper_function_reconstuct_and_test(t, n, [1, 4, 2])
    
    @pytest.mark.skip(reason="Disable for performance reasons")
    def test_all_reconstuctions(self):
        # Set (t,n)-threshold parameters
        n = 20
        t = 5
        (expected_decryption, S_list, p) = self.helper_function_reconstruct(t, n)

        possible_indexes = range(n)
        permutations = itertools.combinations(possible_indexes, t)

        for permutation in permutations:
            S_list_local = [S_list[i] for i in permutation]
            index_list = [i+1 for i in permutation]
            actual_decryption = pvss.decode(S_list_local, index_list, p)

            assert expected_decryption == actual_decryption

    def test_gen_polynomial(self):
        Gq = EcGroup()
        p = Gq.order()
        
        px = pvss.gen_polynomial(3, 42, p)
        for pi in px:
            assert pi < p

    def test_X_i_calc(self):
        Gq = EcGroup()
        p = Gq.order()
        g = Gq.generator()
        
        # Decide on a secret to be distributed
        m = p.from_binary(b'This is a test')

        t = 3
        n = 4

        secret = m
        px = pvss.gen_polynomial(t, secret, p)

        commitments = pvss.get_commitments(g, px)
        shares_list = pvss.calc_shares(px, t, n, p)

        X_list = cpni.get_X_i_list(commitments, n)

        X_list_verify = [share * g for share in shares_list]

        for (x1, x2) in zip(X_list, X_list_verify):
            assert x1 == x2
