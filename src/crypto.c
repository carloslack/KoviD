#include <linux/module.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/version.h>
#include "lkm.h"
#include "log.h"
#include "crypto.h"

/** internal use transformation handle */
static struct crypto_skcipher *tfm;

/**
 * Setup encryption key
 * Must be called once from KoviD initialization
 */
int kv_crypto_key_init(void) {
    static char key[ENCKEY_LEN] = {0};
    int rc;

    /** Allocate AES-CBC */
    if (!crypto_has_skcipher("cbc(aes)", 0, 0)) {
        prerr("Cipher not found\n");
        return 0;
    }

    /** Allocate for transformation
     * Shared across all instances
     */
    tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        prerr("Failed to allocate cipher %d\n", PTR_ERR(tfm));
        return 0;
    }

    memcpy(key, ENCKEY, ENCKEY_LEN);

    /** Finally, set the key */
    rc = crypto_skcipher_setkey(tfm, key, ENCKEY_LEN);
    if (rc < 0) {
        prerr("Key init error %d\n", rc);
        crypto_free_skcipher(tfm);
        return 0;
    }

    return rc;
}

/** Encryption init
 * Called for each encryption operation */
struct kv_crypto_st *crypto_init(void) {
    struct kv_crypto_st *kvmgc = kmalloc(sizeof(struct kv_crypto_st), GFP_KERNEL);
    if (!kvmgc) {
        prerr("Failed to allocate memory for vars\n");
        return -ENOMEM;
    }

    kvmgc->req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!kvmgc->req) {
        prerr("Failed to allocate request\n");
        return NULL;
    }

    /** Generate a random IV each time */
    get_random_bytes(kvmgc->iv, sizeof(kvmgc->iv));

    return kvmgc;
}

size_t kv_encrypt(struct kv_crypto_st *kvmgc, u8 *data, size_t datalen) {
    char plaintext[datalen];
    size_t copied;
    int rc;
    u8 iv_orig[16] = {0};

    if (!kvmgc) {
        prerr("Invalid decrypt ptr\n");
        return 0;
    }

    memcpy(plaintext, data, datalen);

    /** debug */
    print_hex_dump(KERN_DEBUG, "plain text: ", DUMP_PREFIX_NONE, 16, 1, plaintext, datalen, true);

    memcpy(iv_orig, kvmgc->iv, sizeof(kvmgc->iv));

    sg_init_one(&kvmgc->sg, plaintext, datalen);
    skcipher_request_set_crypt(kvmgc->req, &kvmgc->sg, &kvmgc->sg, datalen, kvmgc->iv);

    /** encrypt */
    rc = crypto_skcipher_encrypt(kvmgc->req);
    if (rc < 0) {
        prerr("Encryption failed %d\n", rc);
        return 0;
    }

    copied = sg_copy_to_buffer(&kvmgc->sg, 1, data, datalen);
    if (copied < datalen) {
        prerr("encrypted count mismatch, expected %lu, copied %d\n", datalen, copied);
        return 0;
    }

    print_hex_dump(KERN_DEBUG, "encrypted text: ", DUMP_PREFIX_NONE, 16, 1, data, datalen, true);

    memcpy(kvmgc->iv, iv_orig, sizeof(kvmgc->iv));

    kvmgc->data = data;
    kvmgc->datalen = datalen;

    return copied;
}

size_t kv_decrypt(struct kv_crypto_st *kvmgc) {
    size_t copied;

    if (!kvmgc) {
        prerr("Invalid decrypt ptr\n");
        return 0;
    }
    size_t datalen = kvmgc->datalen;
    char plaintext[datalen];
    int err = 0;

    memset(plaintext, 0, datalen);

    sg_init_one(&kvmgc->sg, kvmgc->data, datalen);
    skcipher_request_set_crypt(kvmgc->req, &kvmgc->sg, &kvmgc->sg, datalen, kvmgc->iv);

    /** decrypt */
    err = crypto_skcipher_decrypt(kvmgc->req);
    if (err) {
        prerr("Decryption failed\n");
    }

    copied = sg_copy_to_buffer(&kvmgc->sg, 1, plaintext, datalen);
    if (copied < datalen) {
        prerr("encrypted count mismatch, expected %lu, copied %d\n", datalen, copied);
        return 0;
    }

    /** XXX dump decrypted data somewhere */
    print_hex_dump(KERN_DEBUG, "decrypted text: ",
            DUMP_PREFIX_NONE, 16, 1, plaintext, datalen, true);

    kfree(kvmgc->data);
    kvmgc->data = NULL;

    return copied;
}

void kv_crypto_mgc_deinit(struct kv_crypto_st *kvmgc) {
    if (kvmgc)
        kv_mem_free(&kvmgc->req, &kvmgc);
}

void kv_crypto_deinit(void) {
    if (tfm) {
        kfree(tfm);
        tfm = NULL;
    }
}
