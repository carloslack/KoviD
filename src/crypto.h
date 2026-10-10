#ifndef __CRYPTO_H
#define __CRYPTO_H

/// 128-bits cipher block
#define CRYPTO_KEY_LEN 16

struct kv_data_st {
	u8 *buf;
	size_t buflen;
};

struct kv_crypto_validate_st {
	bool ok;
	uint64_t address_value;
};

struct kv_crypto_st {
	u8 iv[16];
	struct scatterlist sg;
	struct skcipher_request *req;
	struct kv_data_st kv_data;
};

#endif
