package org.codelightful.harpo;

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.File;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAUtilTest {
    RSAUtil classUnderTest = RSAUtil.getInstance();

    /** Test the scenario when the encrypt method is invoked with a null string */
    @Test
    public void testEncryptWithNullString() {
        PublicKey mockedKey = Mockito.mock(PublicKey.class);
        String result = classUnderTest.encrypt(mockedKey, null);
        Assert.assertNull(result);
    }

    /** Test the scenario when the decrypt method is invoked with a null string */
    @Test
    public void testDecryptWithNullString() {
        PrivateKey mockedKey = Mockito.mock(PrivateKey.class);
        String result = classUnderTest.decrypt(mockedKey, null);
        Assert.assertNull(result);
    }

    /** Test the process of encrypting and decrypting a text using RSA keys */
    @Test
    public void testEncryptDecryptWithPrivateKey() {
        KeyPair keyPair = classUnderTest.createKeyPair(1024);

        String toEncrypt = "This is a sample test to be encrypted";
        String encrypted = classUnderTest.encrypt(keyPair.getPublic(), toEncrypt);
        Assert.assertNotNull(encrypted);

        String decrypted = classUnderTest.decrypt(keyPair.getPrivate(), encrypted);
        Assert.assertEquals(decrypted, toEncrypt);
    }

    /** Test the generation, serialization and deserialization of keys */
    @Test
    public void testSerializeAndDeserializeKey() {
        String tempFolder = System.getProperty("java.io.tmpdir");
        Assert.assertNotNull(tempFolder, "Temp folder not found");
        RSAUtil.FileSystemStorage storage = new RSAUtil.FileSystemStorage(tempFolder);
        File privateKeyFile = null;
        File publicKeyFile = null;

        try {
            KeyPair keyPair = classUnderTest.createKeyPair(1024, storage);
            Assert.assertNotNull(keyPair);

            privateKeyFile = storage.getPrivateKeyFile();
            Assert.assertTrue(privateKeyFile.exists());
            publicKeyFile = storage.getPublicKeyFile();
            Assert.assertTrue(publicKeyFile.exists());

            KeyPair extractedKey = classUnderTest.getKeyPair(storage);
            Assert.assertNotNull(extractedKey);
            Assert.assertNotNull(extractedKey.getPrivate());
            Assert.assertNotNull(extractedKey.getPublic());
            Assert.assertEquals(keyPair.getPrivate(), extractedKey.getPrivate());
            Assert.assertEquals(keyPair.getPublic(), extractedKey.getPublic());
        } finally {
            if(privateKeyFile != null) {
                if(!privateKeyFile.delete()) {
                    System.err.print("Unable to remove a temporary filesystem test file:");
                    System.err.println(privateKeyFile.getAbsolutePath());
                }
            }
            if(publicKeyFile != null) {
                if(!publicKeyFile.delete()) {
                    System.err.print("Unable to remove a temporary filesystem test file:");
                    System.err.println(publicKeyFile.getAbsolutePath());
                }
            }
        }
    }
}