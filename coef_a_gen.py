from ref import reference as lib

pubkeys = [
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661",
        "020000000000000000000000000000000000000000000000000000000000000007"
    ]

test_vecs = [
    [0, 1, 2],
    [1, 0, 2],
    [1, 2, 0],
    [0, 1],
    [0, 1, 2],
    [0, 1, 2]
]

current_signer_vec = [
    0, 1, 2, 0, 0, 0
]

pubkeys_bytes = lib.fromhex_all(pubkeys)

for test_vec, curr_signer, i in zip(test_vecs, current_signer_vec, range(0, len(current_signer_vec))):
    pubkeys_round = [pubkeys_bytes[i] for i in test_vec]
    pubkeys_round_sorted = lib.key_sort(pubkeys_round)
    coef_a = lib.key_agg_coeff(pubkeys_round_sorted, pubkeys_bytes[curr_signer])
    aggkey = lib.key_agg(pubkeys_round_sorted).Q
    print(f"====TEST {i} DATA====")
    print("CoefA: " + lib.bytes_from_int(coef_a).hex().upper())
    print("Aggkey: " + lib.cbytes(aggkey).hex().upper())