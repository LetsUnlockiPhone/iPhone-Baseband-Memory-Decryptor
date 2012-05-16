iPhone-Baseband-Memory-Decryptor
================================

When testing a network code key, the baseband firmware reads the encryptedSignature, calculates the deviceKey and the nckKey from the entered NCK, decrypts the encryptedSignature with the nckKey using TEA, decrypts it once more with the public RSA key and verifies the signature with the SHA1 hashes of the chipID / norID.