from ref import reference as lib

pk_grp = [
    "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
    "02D2DC6F5DF7C56ACF38C7FA0AE7A759AE30E19B37359DFDE015872324C7EF6E05"
]

pk_grp = lib.fromhex_all(lib.key_sort(pk_grp))
aggpk_grp = lib.key_agg(pk_grp).Q

print(lib.xbytes(aggpk_grp).hex().upper())