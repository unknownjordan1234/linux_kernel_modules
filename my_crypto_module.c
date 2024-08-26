#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/slab.h>

#define AES_KEY_LEN 16 // Key length for AES-128
#define AES_BLOCK_SIZE 16 // Block size for AES
#define DATA_SIZE 16 // Size of the data to encrypt / decrypt

static char key[AES_KEY_LEN] = "mysecretkey123"; // Example AES key
static char data[DATA_SIZE] = "Hello, World!"; // Data to be encrypted
static char encrypted[DATA_SIZE]; // Buffer for encrypted data
static char decrypted[DATA_SIZE]; // Buffer for decrypted data

static int __init my_crypto_init(void) {
    struct crypto_blkcipher *tfm;
    struct blkcipher_desc desc;
    struct scatterlist sg_enc, sg_dec;
    int result;

    // Allocate the transformation context
    tfm = crypto_alloc_blkcipher("aes", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate transformation context\n");
        return PTR_ERR(tfm);
    }

    // Set the encryption key
    result = crypto_blkcipher_setkey(tfm, key, AES_KEY_LEN);
    if (result) {
        printk(KERN_ERR "Failed to set encryption key\n");
        crypto_free_blkcipher(tfm);
        return result;
    }

    // Encrypt the data
    sg_init_one(&sg_enc, data, DATA_SIZE);
    desc.tfm = tfm;
    desc.flags = 0;

    result = crypto_blkcipher_encrypt(&desc, &sg_enc, &sg_enc, DATA_SIZE);
    if (result) {
        printk(KERN_ERR "Encryption failed\n");
        crypto_free_blkcipher(tfm);
        return result;
    }

    // Store encrypted data
    memcpy(encrypted, sg_virt(&sg_enc), AES_BLOCK_SIZE);
    printk(KERN_INFO "Encrypted data: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printk("%02x ", (unsigned char)encrypted[i]);
    }
    printk("\n");

    // Decrypt the data
    sg_init_one(&sg_dec, encrypted, DATA_SIZE);
    result = crypto_blkcipher_decrypt(&desc, &sg_dec, &sg_dec, DATA_SIZE);
    if (result) {
        printk(KERN_ERR "Decryption failed\n");
        crypto_free_blkcipher(tfm);
        return result;
    }

    // Store decrypted data
    memcpy(decrypted, sg_virt(&sg_dec), DATA_SIZE);
    printk(KERN_INFO "Decrypted data: %s\n", decrypted);

    // Clean up
    crypto_free_blkcipher(tfm);
    return 0;
}

static void __exit my_crypto_exit(void) {
    printk(KERN_INFO "Cryptography module exited.\n");
}

module_init(my_crypto_init);
module_exit(my_crypto_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple Linux kernel module for AES encryption and decryption");
