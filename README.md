# 🔐 JWT Security with Asymmetric Encryption

This guide explains the importance of **asymmetric encryption** in securing JWTs (JSON Web Tokens), how to generate your private/public keys, and compares symmetric and asymmetric encryption approaches.

---

## 📌 Why Asymmetric Encryption?

Asymmetric encryption enhances security by using **two keys**: a **private key** to sign the token and a **public key** to verify it.

### Key Benefits:
- ✅ The **private key** remains secure on the server and is never shared.
- ✅ The **public key** can be distributed to any service or client that needs to verify the token.
- ✅ Ideal for **microservices**, **3rd-party integrations**, and **stateless authentication**.

---

## 🔧 How to Generate RSA Key Pair

You can use `openssl` to generate the keys from the command line:

### 1. Generate a 2048-bit Private Key
```bash
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```

### 2. Extract the Public Key from the Private Key
```bash
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

Now you have:
- `private_key.pem` — used to **sign** JWTs
- `public_key.pem` — used to **verify** JWTs

---

## 🔐 Symmetric vs Asymmetric Encryption

| Feature                  | Symmetric Encryption             | Asymmetric Encryption                 |
|--------------------------|----------------------------------|---------------------------------------|
| 🔑 Keys                  | One shared secret key            | Public key and private key pair       |
| 📦 Token Signing & Verifying | Same key is used for both       | Private key signs, public key verifies |
| 🔒 Key Sharing Risk      | High — must be shared securely   | Low — public key is openly sharable   |
| 🤝 Use Case              | Internal APIs, small-scale apps  | Public APIs, microservices, JWTs      |
| ⚡ Performance           | Faster                           | Slightly slower                       |
| 🛡️ Security              | Less secure in distributed setup | Stronger in distributed systems       |

---

## ✅ Summary

- Asymmetric encryption is **essential for secure JWT authentication**, especially in distributed systems or when exposing public APIs.
- It separates the concerns of **signing (server-only)** and **verification (client/multiple services)**.
- You should never expose your **private key** and always store it securely (e.g., in a vault or secure secrets manager).

---

🛡️ *Security is not a feature — it's a responsibility.*
