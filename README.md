iPhone Baseband Decryptor
================================

When testing a network code key, the baseband firmware reads the encryptedSignature, calculates the deviceKey and the nckKey from the entered NCK, decrypts the encryptedSignature with the nckKey using TEA, decrypts it once more with the public RSA key and verifies the signature with the SHA1 hashes of the chipID / norID.

Two identification numbers unique to each device are generated from the NOR flash and baseband CPU serials: the norID and the chipID, 8 respectively 12 bytes in size.
The device-specific deviceKey is generated from truncating a SHA1 hash of the concatenated and padded norID and chipID.
A supposedly random NCK (‘network control key’) is SHA1-hashed. With the hashed NCK and the norID and chipID, the second key nckKey is generated. The hashing algorithm uses Tiny Encryption Algorithm (TEA). The nckKey is also device-specific since both the norID and chipIDare used.
A device-specific RSA signature is generated: two SHA1 hashes are generated from the norID and chipID. The status that the lock has after the correct NCK has been entered is also embedded into this message. The PCKS 1.5 format is used to pad the hashes and the status from (2*160+32) bit to 2048 bit (256 byte).
The asymmetric RSA algorithm is used for the encryption of the unlock signature. Keep in mind that the algorithm uses two different keys: a private key for encryption and a public key for decryption. With the private RSA key, the signature is encrypted and stored in protected memory.
This signature is encrypted with TEA once again using the device-specific deviceKey in CBC mode.

This script will extract all tokens, required to have memory dumped into binary file.
================================
Here is Dev-team NOR Dumper implementation/
http://www.letsunlockiphone.com/dump-iphone-baseband-nor-memory-nordumper/

Sample of using this script:
================================
http://www.letsunlockiphone.com/dump-iphone-baseband-nor-memory-nordumper/

Big thanks to @Dogbert for awesome script.
http://dogber1.blogspot.com