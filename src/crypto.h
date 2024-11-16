#ifndef __CRYPTO_H
#define __CRYPTO_H

struct kv_data_st {
    u8 *buf;
    size_t buflen;
};

struct kv_crypto_st {
    u8 iv[16];
    struct scatterlist sg;
    struct skcipher_request *req;
    struct kv_data_st kv_data;
};

#endif
