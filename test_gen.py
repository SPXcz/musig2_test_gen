import pandas as pd
import random as rnd
import numpy as np
from ref import reference as lib

NO_OF_TESTS = 30
MAX_KEY_VALUE = 2**256-1
MAX_MESSAGE_LEN = 255

def gen_keygen_data():

    pks = []
    sks = []

    for _ in range(0, NO_OF_TESTS):

        sk = rnd.randint(0, MAX_KEY_VALUE)
        pk = lib.cbytes(lib.point_mul(lib.G, sk))

        pks.append(pk.hex().upper())
        sks.append(lib.bytes_from_int(sk).hex().upper())
    
    out_df = pd.DataFrame({
        'privateKey': np.array(sks),
        'publicKeyOut': np.array(pks)
    })

    out_df.to_csv('data/keygen_test.csv')

def gen_noncegen_data():

    no_of_participants = []
    pks = []
    aggpks = []
    secnonces = []
    pubnonces = []

    for _ in range(0, NO_OF_TESTS):
        
        # Generate aggpk and pk
        pk = get_rand_pk()

        if rnd.randint(0,5) < 5:
            no_of_participants_grp = rnd.randint(1, 10)+1
            pk_grp = [get_rand_pk() for _ in range(0, no_of_participants_grp)]
            pk_grp.append(pk)
            pk_grp = lib.key_sort(pk_grp)
            aggpk_grp = lib.key_agg(pk_grp).Q

            # Generate aggnonce and secnonce
            secnonce, pubnonce = lib.nonce_gen(None, pk, lib.xbytes(aggpk_grp), None, None)
        else:
            no_of_participants_grp = 0
            pk_grp = []
            aggpk_grp = None

            # Generate aggnonce and secnonce
            secnonce, pubnonce = lib.nonce_gen(None, pk, None, None, None)

        no_of_participants.append(no_of_participants_grp)
        pks.append(pk.hex().upper())
        aggpks.append(lib.cbytes(aggpk_grp).hex().upper() if aggpk_grp is not None else None)
        secnonces.append(secnonce.hex().upper())
        pubnonces.append(pubnonce.hex().upper())
    
        out_df = pd.DataFrame({
            'publicKey': np.array(pks),
            'expectedSecNonce': np.array(secnonces),
            'expectedPubNonce': np.array(pubnonces),
            'aggregatePublicKey': np.array(aggpks),
            'noOfParticipants': np.array(no_of_participants)
        })

        out_df.to_csv('data/noncegen_test.csv')


def gen_sign_data():
    
    sks = []
    aggpks = []
    secnonces = []
    aggnonces = []
    coef_as = []
    messages = []
    signatures = []
    no_of_participants = []

    for _ in range(0, NO_OF_TESTS):

        sk = rnd.randint(1, MAX_KEY_VALUE)
        pk = lib.cbytes(lib.point_mul(lib.G, sk))

        # Generate aggpk and coef_a of the group
        no_of_participants_grp = rnd.randint(1, 10)+1
        sk_grp, pk_grp, current_signer_index = get_sorted_sk_pk(no_of_participants_grp, sk, pk)
        coef_a = lib.key_agg_coeff_internal(pk_grp, pk, lib.get_second_key(pk_grp))
        aggpk_grp = lib.key_agg(pk_grp).Q

        # Generate aggnonce
        secnonces_grp = []
        pubnonces_grp = []
        nonces = [lib.nonce_gen(None, pk_cosigner, lib.xbytes(aggpk_grp), None, None) for pk_cosigner in pk_grp]

        for nonce in nonces:
            secnonces_grp.append(nonce[0])
            pubnonces_grp.append(nonce[1])

        secnonces.append(secnonces_grp[current_signer_index].hex().upper())
        aggnonce = lib.nonce_agg(pubnonces_grp)

        # Sign
        message_len = rnd.randint(1, MAX_MESSAGE_LEN)
        message = rnd.randbytes(message_len)
        psigs = sign_partial(secnonces_grp, sk_grp, aggnonce, pk_grp, message)
        agg_sig = sig_agg(psigs, aggnonce, pk_grp, message)

        sks.append(lib.bytes_from_int(sk).hex().upper())
        aggpks.append(lib.cbytes(aggpk_grp).hex().upper())
        aggnonces.append(aggnonce.hex().upper())
        coef_as.append(lib.bytes_from_int(coef_a).hex().upper())
        messages.append(message.hex().upper())
        signatures.append(agg_sig.hex().upper())
        no_of_participants.append(no_of_participants_grp)

    out_df = pd.DataFrame({
        'privateKey': sks,
        'aggnonce': aggnonces,
        'secnonce': secnonces,
        'coefA': coef_as,
        'aggregatePublicKeyTest': aggpks,
        'expectedSignature': signatures,
        'messages': messages,
        'noOfParticipants': no_of_participants,
    })

    out_df.to_csv('data/sign_test.csv')


def get_sk_pk() -> tuple[int, bytes]:
    sk = rnd.randint(0, MAX_KEY_VALUE)
    return sk, lib.cbytes(lib.point_mul(lib.G, sk))

def get_rand_pk() -> bytes:
    sk = rnd.randint(0, MAX_KEY_VALUE)
    return lib.cbytes(lib.point_mul(lib.G, sk))

def get_sorted_sk_pk(no_of_participants_grp: int, sk: int, pk: bytes) -> tuple[list[int], list[bytes], int]:
    '''
    Returns sorted array of public shares, secret shares and the index of the current signer
    '''
    keypair_grp = [get_sk_pk() for _ in range(0, no_of_participants_grp)]
    keypair_grp.append((sk, pk))
    keypair_grp = tuple(sorted(keypair_grp, key=lambda x: x[1])) # Not sorted using the reference sort function
    sk_grp = [keypair[0] for keypair in keypair_grp]
    pk_grp = [keypair[1] for keypair in keypair_grp]

    return sk_grp, pk_grp, pk_grp.index(pk)

def sign_partial(secnonces, sks, aggnonce, pubkeys, msg) -> list[bytes]:
    session_ctx = (aggnonce, pubkeys, [], [], msg)
    psigs = []
    
    for secnonce, sk in zip(secnonces, sks):
        psig = lib.sign(secnonce, lib.bytes_from_int(sk), session_ctx)
        psigs.append(psig)
    
    return psigs

def sig_agg(psigs, aggnonce, pubkeys, msg):
    session_ctx = (aggnonce, pubkeys, [], [], msg)
    return lib.partial_sig_agg(psigs, session_ctx)

def main():
    #gen_sign_data()
    #gen_keygen_data()
    gen_noncegen_data()

if __name__ == "__main__":
    main()