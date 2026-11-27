# EX-NO-9-RSA-Algorithm

## AIM:
To Implement RSA Encryption Algorithm in Cryptography

## Algorithm:


Step 1: Design of RSA Algorithm  
The RSA algorithm is based on the mathematical difficulty of factoring the product of two large prime numbers. It involves generating a public and private key pair, where the public key is used for encryption, and the private key is used for decryption.

Step 2: Implementation in Python or C 
This algorithm can be implemented in languages like Python or C by performing large integer calculations for key generation, encryption, and decryption, utilizing libraries for modular arithmetic if necessary.

Step 3: Algorithm Description  
1. Key Generation:
   - Select two large prime numbers \( p \) and \( q \).
   - Calculate \( n = p \times q \), which will be used as the modulus.
   - Compute the totient \( \phi(n) = (p - 1)(q - 1) \).
   - Choose a public exponent \( e \) such that \( e \) is coprime with \( \phi(n) \).
   - Compute the private key \( d \), which is the modular inverse of \( e \) mod \( \phi(n) \).

2. Encryption:
   - Convert the plaintext message \( M \) into a numerical form \( m \) (such that \( 0 \le m < n \)).
   - Compute the ciphertext \( c \) using the formula: \( c = m^e \mod n \).

3. Decryption:
   - Use the private key \( d \) to recover \( m \) from \( c \) using: \( m = c^d \mod n \).
   - Convert \( m \) back into the original message \( M \).

Step 4: Mathematical Representation  
- Encryption: \( E(m) = m^e \mod n \)
- Decryption: \( D(c) = c^d \mod n \)

Step 5: **Security Foundation  
The security of RSA relies on the difficulty of factoring large numbers; thus, choosing sufficiently large prime numbers for \( p \) and \( q \) is crucial for security.

## Program:
```
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>


#define MAX_PRIME_INPUT 46340


static int read_uint64(const char *prompt, uint64_t *value)
{
    char line[128];
    char *start, *end;
    unsigned long long parsed;


    printf("%s", prompt);
    if (!fgets(line, sizeof line, stdin))
        return 0;


    start = line;
    while (isspace((unsigned char)*start))
        ++start;
    if (*start == '-')
        return 0;


    errno = 0;
    parsed = strtoull(start, &end, 10);
    if (start == end || errno == ERANGE)
        return 0;
    while (isspace((unsigned char)*end))
        ++end;
    if (*end != '\0' || (unsigned long long)(uint64_t)parsed != parsed)
        return 0;


    *value = (uint64_t)parsed;
    return 1;
}


static int is_prime(uint64_t value)
{
    if (value < 2)
        return 0;
    for (uint64_t divisor = 2; divisor <= value / divisor; ++divisor) {
        if (value % divisor == 0)
            return 0;
    }
    return 1;
}


static uint64_t gcd(uint64_t a, uint64_t b)
{
    while (b != 0) {
        uint64_t remainder = a % b;
        a = b;
        b = remainder;
    }
    return a;
}


static uint64_t mod_pow(uint64_t base, uint64_t exponent, uint64_t modulus)
{
    uint64_t result = 1;
    base %= modulus;
    while (exponent > 0) {
        if (exponent & 1)
            result = (result * base) % modulus;
        base = (base * base) % modulus;
        exponent >>= 1;
    }
    return result;
}


static int mod_inverse(uint64_t value, uint64_t modulus, uint64_t *inverse)
{
    int64_t t = 0, next_t = 1;
    int64_t remainder = (int64_t)modulus, next_remainder = (int64_t)value;


    while (next_remainder != 0) {
        int64_t quotient = remainder / next_remainder;
        int64_t temp = t - quotient * next_t;
        t = next_t;
        next_t = temp;
        temp = remainder - quotient * next_remainder;
        remainder = next_remainder;
        next_remainder = temp;
    }
    if (remainder != 1)
        return 0;
    if (t < 0)
        t += (int64_t)modulus;
    *inverse = (uint64_t)t;
    return 1;
}


int main(void)
{
    uint64_t p, q, n, phi, e, m, d, ciphertext;


    if (!read_uint64("Enter prime p (2-46340): ", &p) ||
        !read_uint64("Enter prime q (2-46340): ", &q)) {
        fprintf(stderr, "Invalid integer input.\n");
        return 1;
    }
    if (p > MAX_PRIME_INPUT || q > MAX_PRIME_INPUT) {
        fprintf(stderr, "p and q must be no greater than %d.\n",
                MAX_PRIME_INPUT);
        return 1;
    }
    if (!is_prime(p)) {
        fprintf(stderr, "p is not a prime number.\n");
        return 1;
    }
    if (!is_prime(q)) {
        fprintf(stderr, "q is not a prime number.\n");
        return 1;
    }
    if (p == q) {
        fprintf(stderr, "p and q must be different prime numbers.\n");
        return 1;
    }


    n = p * q;
    phi = (p - 1) * (q - 1);
    printf("n = p * q = %llu\n", (unsigned long long)n);
    printf("phi(n) = (p - 1) * (q - 1) = %llu\n",
           (unsigned long long)phi);


    if (!read_uint64("Enter public exponent e (2-1000): ", &e)) {
        fprintf(stderr, "Invalid integer input for e.\n");
        return 1;
    }
    if (e < 2 || e > 1000 || e >= phi || gcd(e, phi) != 1) {
        fprintf(stderr, "e must be between 2 and 1000, less than phi(n), "
                "and coprime to phi(n).\n");
        return 1;
    }


    if (!read_uint64("Enter numeric message m (0 <= m < n): ", &m)) {
        fprintf(stderr, "Invalid integer input for m.\n");
        return 1;
    }
    if (m >= n) {
        fprintf(stderr, "m must be less than n.\n");
        return 1;
    }


    ciphertext = mod_pow(m, e, n);
    if (!mod_inverse(e, phi, &d)) {
        fprintf(stderr, "Could not compute the private exponent.\n");
        return 1;
    }


    printf("Public key (e, n): (%llu, %llu)\n",
           (unsigned long long)e, (unsigned long long)n);
    printf("Private key (d, n): (%llu, %llu)\n",
           (unsigned long long)d, (unsigned long long)n);
    printf("Encryption: c = m^e mod n = %llu\n",
           (unsigned long long)ciphertext);
    printf("Decryption check: m = c^d mod n = %llu\n",
           (unsigned long long)mod_pow(ciphertext, d, n));
    return 0;
}


```



## Output:

<img width="307" height="201" alt="image" src="https://github.com/user-attachments/assets/56a166da-e187-4830-9761-13df5b99c392" />


## Result:
 The program is executed successfully.
