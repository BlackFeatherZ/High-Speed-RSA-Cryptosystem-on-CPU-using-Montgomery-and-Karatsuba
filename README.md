# High-Speed-RSA-Cryptosystem-on-CPU-using-Montgomery-and-Karatsuba
Goal: Implement a high speed RSA cryptosystem by using software programming languages on x86 computers.

Major Functions:
• Support both RSA encryption and decryption (use public key to encrypt and secrete key to decrypt).
• Support 4096-bit keysize.
• Support 1024-bit message encryption and decryption.
• A timer in the RSA system to record the encryption and decryption time.

Improvement compared to the original implementation:
Reduced the time complexity of multiplication and modular multiplication, and improved the running time of the algorithm by 10ms in encryption and 200ms in decryption using Montgomery modular multiplication Algorithm and Karatsuba algorithm.
