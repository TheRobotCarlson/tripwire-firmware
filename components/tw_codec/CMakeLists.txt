idf_component_register(
    SRCS "tw_codec.c" "tw_aead_psa.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES mbedtls
)
