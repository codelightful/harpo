# Harpo
A light-weight Java library with encryption utilities


###RSA Util
An utility class that allows to create and load RSA keys and to execute encryption/decryption with those.

#####Usage:
Creating a new RSA keys:
```
// creating RSA keys with 1024 bytes
KeyPair pair = RSAUtil.getInstance().createKeyPair(1024);
```

Encrypting text using a public key
```
String encrypted = RSAUtil.getInstance().encrypt(publicKey, "Text to encrypt");
```

Decrypting text using a private key
```
String decrypted = RSAUtil.getInstance().decrypt(privateKey, "WTDNk0BN1vXMDQmmoIRvxXOb3Vw5Sb5HLfSUVcw5WTxJ2NQrQnBCWF8z7jvcMN9ZGYaQ1b9OxNJ/KAM/yTL2YdaZU4Ute+RXzsHJwRUWPRalVN62889LxDOHRT+sNs+HkbGzXw1wFLddUPUpaYAgSzGruojoq0YsCermkvNv1zA=");
```