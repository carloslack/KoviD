#ifndef __CRYPTO_H
#define __CRYPTO_H

struct kv_crypto_st {
    u8 iv[16];
    struct scatterlist sg;
    struct skcipher_request *req;
    u8 *data;
    size_t datalen;
};

#endif
