package org.codelightful.harpo;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Class with utility methods for RSA */
public class
RSAUtil {
    /** Constant with the name of the RSA algorithm */
    public static final String RSA_ALGORITHM = "RSA";

    /** Singleton instance */
    private static RSAUtil instance;
    /** Holds the singleton instance for the class used for RSA encryption */
    private static ThreadLocal<Cipher> encryptCipher = new ThreadLocal<>();
    /** Holds the singleton instance for the class used for RSA decryption */
    private static ThreadLocal<Cipher> decryptCipher = new ThreadLocal<>();

    /** Internal instance to create the key factory */
    private KeyFactory keyFactory;

    private RSAUtil() {
        try {
            keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        } catch (Exception ex) {
            throw new RuntimeException("An error has ocurred creating a RSA key factory");
        }
    }

    /** Allows to obtain the singleton instance */
    public static RSAUtil getInstance() {
        if(instance == null) {
            synchronized (RSAUtil.class) {
                if(instance == null) {
                    instance = new RSAUtil();
                }
            }
        }
        return instance;
    }

    /**
     * Encrypts a string using a RSA key
     * @param publicKey RSA public key to use
     * @param toEncrypt String to encrypt
     */
    public String encrypt(PublicKey publicKey, String toEncrypt) {
        if(toEncrypt == null) {
            return null;
        }
        try {
            Cipher cipher = getCipher(encryptCipher, Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(toEncrypt.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            throw new RuntimeException("An error has occurred trying to encrypt a string", ex);
        }
    }

    /**
     * Decrypts a string using a RSA key
     * @param privateKey RSA private key to use
     * @param toDecrypt String to decrypt
     */
    public String decrypt(PrivateKey privateKey, String toDecrypt) {
        if(toDecrypt == null) {
            return null;
        }
        try {
            Cipher cipher = getCipher(decryptCipher, Cipher.DECRYPT_MODE, privateKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(toDecrypt);
            byte[] decrypted = cipher.doFinal(encryptedBytes);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new RuntimeException("An error has occurred trying to decrypt a string", ex);
        }
    }

    /** Allows to obtain a RSA cipher from a specific private key */
    private Cipher getCipher(ThreadLocal<Cipher> threadLocal, int mode, Key key) throws Exception {
        Cipher cipher = threadLocal.get();
        if(cipher == null) {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(mode, key);
            threadLocal.set(cipher);
        }
        return cipher;
    }

    /**
     * Generates a RSA keypair with a specific key size
     * @param keySize The size to generate the RSA keys
     */
    public KeyPair createKeyPair(int keySize) {
        try {
            KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            pairGenerator.initialize(keySize);
            return pairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new RuntimeException("An error has occurred generating an RSA key pair", ex);
        }
    }

    /**
     * Generates a RSA key pair and serialize it using a specific implementation
     * @param keySize The size to generate the RSA keys
     * @param keyStorage The instance used to store the keys
     */
    public KeyPair createKeyPair(int keySize, KeyStorage keyStorage) {
        KeyPair keyPair = createKeyPair(keySize);
        if(keyStorage != null) {
            keyStorage.serialize(keyPair);
        }
        return keyPair;
    }

    /**
     * Allows to obtain a private key from a repository
     * @param keyStorage Instance to load the key content from it
     */
    public PrivateKey getPrivateKey(KeyStorage keyStorage) {
        byte[] content = keyStorage.getPrivateKeyContent();
        return getPrivateKey(content);
    }

    /**
     * Allows to obtain a public key from a repository
     * @param keyStorage Instance to load the key content from it
     */
    public PublicKey getPublicKey(KeyStorage keyStorage) {
        byte[] content = keyStorage.getPublicKeyContent();
        return getPublicKey(content);
    }

    /**
     * Allows to obtain a key pair from a repository
     * @param keyStorage Instance to load the key content from it
     */
    public KeyPair getKeyPair(KeyStorage keyStorage) {
        PrivateKey privateKey = getPrivateKey(keyStorage);
        PublicKey publicKey = getPublicKey(keyStorage);
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Generates a public key from a specific byte content
     * @param keyContent Byte content for the key to produce
     */
    public PublicKey getPublicKey(byte[] keyContent) {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyContent);
        try {
            return keyFactory.generatePublic(spec);
        } catch (Exception ex) {
            throw new RuntimeException("An error has occurred trying to load a public key", ex);
        }
    }

    /**
     * Generates a private key from a specific byte content
     * @param keyContent Byte content for the key to produce
     */
    public PrivateKey getPrivateKey(byte[] keyContent) {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyContent);
        try {
            return keyFactory.generatePrivate(spec);
        } catch (Exception ex) {
            throw new RuntimeException("An error has occurred trying to load a public key", ex);
        }
    }

    /** Parent class for all the implementations that allows to store a RSA key in a serialized way */
    public static abstract class KeyStorage {
        /**
         * Serializes a private key using the specific mechanism defined for this instance
         * @param privateKey Key to serialize
         */
        public abstract void serialize(PrivateKey privateKey);

        /**
         * Serializes a public key using the specific mechanism defined for this instance
         * @param publicKey Key to serialize
         */
        public abstract void serialize(PublicKey publicKey);

        /**
         * Extracts the content for the private key from the storage mechanism defined for this instance
         */
        public abstract byte[] getPrivateKeyContent();

        /**
         * Extracts the content for the public key from the storage mechanism defined for this instance
         */
        public abstract byte[] getPublicKeyContent();

        /**
         * Serializes a key pair using the specific mechanism defined for this instance
         * @param keyPair Keypair to serialize
         */
        public void serialize(KeyPair keyPair) {
            if(keyPair != null) {
                serialize(keyPair.getPrivate());
                serialize(keyPair.getPublic());
            }
        }
    }

    /** Storage to save the keys in a filesystem location */
    public static class FileSystemStorage extends KeyStorage {
        /** Constant with the default name used for the private key file */
        public static final String DEFAULT_PRIVATE_KEY_FILENAME = "private.key";
        /** Constant with the default name used for the public key file */
        public static final String DEFAULT_PUBLIC_KEY_FILENAME = "public.key";
        /** File with the the private key */
        private File privateFile;
        /** File with the the public key */
        private File publicFile;

        /**
         * Creates a serializes instance that stores the keys in specific files
         * @param privateFile File with the private key
         * @param publicFile File with the public key
         */
        public FileSystemStorage(File privateFile, File publicFile) {
            this.privateFile = privateFile;
            this.publicFile = publicFile;
        }

        /**
         * Creates a serializes instance that stores the keys in a specific location and filenames
         * @param privateLocation Path and filename to store the private key
         * @param publicLocation Path and filename to store the public key
         */
        public FileSystemStorage(String privateLocation, String publicLocation) {
            this(new File(privateLocation), new File(publicLocation));
        }

        /**
         * Creates a serializes instance that stores the keys in a specific location using the default file names
         * @param location Path to the folder to store the keys on it
         */
        public FileSystemStorage(String location) {
            this(Paths.get(location, DEFAULT_PRIVATE_KEY_FILENAME).toFile(),
                    Paths.get(location, DEFAULT_PUBLIC_KEY_FILENAME).toFile());
        }

        /** Obtains the file where the private key was stored */
        public File getPrivateKeyFile() {
            return this.privateFile;
        }

        /** Obtains the file where the public key was stored */
        public File getPublicKeyFile() {
            return this.publicFile;
        }

        @Override
        public void serialize(PrivateKey privateKey) {
            saveToFile(privateFile, privateKey.getEncoded());
        }

        @Override
        public void serialize(PublicKey publicKey) {
            saveToFile(publicFile, publicKey.getEncoded());
        }

        /**
         * Internal method to save a byte content to a specific file
         * @param file File to save the content on it
         * @param content The content to store in the file
         */
        private void saveToFile(File file, byte[] content) {
            content = Base64.getEncoder().encode(content);
            try(FileOutputStream stream = new FileOutputStream(file)) {
                stream.write(content);
            } catch (Exception ex) {
                throw new RuntimeException("An error has occurred trying to serialize a key to the filesystem", ex);
            }
        }

        @Override
        public byte[] getPrivateKeyContent() {
            try {
                return getKeyContent(this.privateFile);
            } catch (Exception ex) {
                throw new RuntimeException("An error has occurred trying to load the private key content", ex);
            }
        }

        @Override
        public byte[] getPublicKeyContent() {
            try {
                return getKeyContent(this.publicFile);
            } catch (Exception ex) {
                throw new RuntimeException("An error has occurred trying to load the public key content", ex);
            }
        }

        /**
         * Internal method with the implementation to load a key content from a specific location
         * @param keyFile File load the content from it
         * @return Byte array with the content loaded
         */
        private byte[] getKeyContent(File keyFile) throws Exception {
            if(!keyFile.exists()) {
                throw new RuntimeException("The key file could not be found at " + keyFile.getAbsolutePath());
            }
            try(FileInputStream stream = new FileInputStream(keyFile)) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                int readByte;
                while ((readByte = stream.read()) >= 0) {
                    buffer.write(readByte);
                }
                byte[] content = buffer.toByteArray();
                return Base64.getDecoder().decode(content);
            } catch (Exception ex) {
                throw new RuntimeException("An error has occurred trying to read the key from the input stream", ex);
            }
        }
    }
}
