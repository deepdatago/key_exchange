package key_exchange;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.Signature;
import java.util.Base64;

public class test {
    public static void main(String[] args) {
    	
    	// constructor 1
    	String algorithm = "RSA";
		String signatureAlg = "SHA256withRSA";
		int keySize = 4096;
		int certExpireInDays = 365;
		String commonName = "CN=KeyManagerTest";	
    	KeyManager keyManager = new KeyManagerImpl(
    			algorithm, 
    			signatureAlg,
    			keySize,
    			certExpireInDays,
    			commonName);
    	
    	// constructor 2:
    	// KeyManager keyManager = new KeyManagerImpl();
    	
    	String privKeyFileName = "/tmp/privatekey.pem";
    	String publicKeyFileName = "/tmp/publickey.pem";
    	String certificateFileName = "/tmp/certificate.pem";
    	keyManager.generateKeyCertificate(privKeyFileName, publicKeyFileName, certificateFileName);
    	keyManager.generateKeyCertificate(privKeyFileName, publicKeyFileName, null);
    	PrivateKey privateKey = null;
    	PublicKey publicKey = null;
		try {
			privateKey = keyManager.loadPrivateKeyFromRSAPEM(privKeyFileName);
			publicKey = keyManager.loadPublicKeyFromRSAPEM(publicKeyFileName);
	    	// publicKey = keyManager.loadPublicKeyFromRSA_X509_CertificatePEM(certificateFileName);
		} catch (NoSuchProviderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return;
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return;
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return;
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return;
		}
    	String plainText = "MY PLAIN TEXT";
    	String encryptedBase64Str;
    	/*
    	try {
    		String myStr = "P5Mj8RoEE/LgiMRxmMXgjaf8Hfwo4J+Qd6DxJDgeIVV7JpY3YRMlD616R2IRtWleLDEicqGp/6OeW1viY3sVw/ScQZ8eIeq9rWY+q63HyeMmInT7ttcdsfLglJMk8i0qkEmEZXsNS01C8lMib9sLE+DYTJv87l2ZHkpWxdM0qqfsRUc2W9XlbSlQMkcMvEiNMru6i37V1Xixd8McqPpIulVYrHOLOVHMWfZFKWSJkuHq6fh1WPMTV4hdBcbM+u9g7KQt+43epq2zoVFw7EOAGja5wcGbVg1Kngcq8Zt1Qk0pLEcZIcnQuh6C0lcOalrvEtMrgY5KVcozVNlinRdhR66HzoqgS6eN7HF0vc4pzTzz8awJgxP47KoWFRfSwp+8as0C+k1eYKR1xpW+oAzne+FqfYW0F17Gee+VzGVkIFg82Hy9tiypwF/ngxKXywsDgXiS0y8cletOGyVN3Wf8z2EVYNNO4omDJSuTCIRfOZkHiSCCq10bNwIdhTpiU5DqwMDrxOhR6dInJvcO6Tuc/KBcp0yz726NlRaK/dtP6LU6pr8a3mug8N+QMh0VLTUT3FQzu/fQIfy3oEcvWOPK3hwkE8X3lXY+jXVD8pRIdwYv6WPSqvELp6mKaPIdG5trgDjMuvRRKVk51AosqrDonI9+v1a0XsEGqf8sxivdgd8=";
    		String decryptedStr = keyManager.decryptTextBase64(myStr.getBytes(), privateKey);
    		System.out.println("Decrypted text: " + decryptedStr);
    	    
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
    	}    	
    	*/
    	try {
    		encryptedBase64Str = keyManager.encryptTextBase64(plainText.getBytes(), publicKey);
    		System.out.println("Encrypted text: " + encryptedBase64Str);
    		String decryptedStr = keyManager.decryptTextBase64(encryptedBase64Str.getBytes(), privateKey);
    		System.out.println("Decrypted text: " + decryptedStr);
    	    
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
    	}    	
    	
    	String myKey = "5d8324e83dc14336914152775d1bb757";
    	SecretKeySpec key = new SecretKeySpec(myKey.getBytes(), "AES");

        Cipher cipher = null;
		try {
	    	// int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
	    	// System.out.println("max allowed length: " + maxKeyLen);
	    	
			
			cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
	        cipher.init(Cipher.ENCRYPT_MODE, key);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

        byte[] cipherText = new byte[cipher.getOutputSize(plainText.length())];
        int ctLength = 0;
		try {
			ctLength = cipher.update(plainText.getBytes(), 0, plainText.length(), cipherText, 0);
	        ctLength += cipher.doFinal(cipherText, ctLength);
		} catch (ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e)
		{
			e.printStackTrace();
			
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String encodedEncryptedStr = new String(Base64.getEncoder().encode(cipherText));
		System.out.println("encrypted string: " + encodedEncryptedStr);
        // System.out.println(new String(cipherText));
        // System.out.println(ctLength);

        // decryption pass
        byte[] decryptedPlainText = null;
        int ptLength = 0;
        try {
			cipher.init(Cipher.DECRYPT_MODE, key);
			/*
	        decryptedPlainText = new byte[cipher.getOutputSize(ctLength)];
	        ptLength = cipher.update(Base64.getDecoder().decode(encodedEncryptedStr), 0, ctLength, decryptedPlainText, 0);
	        ptLength += cipher.doFinal(decryptedPlainText, ptLength);
	        */
			decryptedPlainText = cipher.doFinal(Base64.getDecoder().decode(encodedEncryptedStr));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e)
		{
			e.printStackTrace();
			
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        System.out.println("decrypted:" + new String(decryptedPlainText)); 
        
        // sign data
        try
        {
	        byte[] data = "012345678901234567890123456789012345678901234567890123456789".getBytes();
	
	        Signature sig = Signature.getInstance(signatureAlg);
	        sig.initSign(privateKey);
	        sig.update(data);
	        byte[] signatureBytes = sig.sign();
	        String encodedSignature = new String(Base64.getEncoder().encode(signatureBytes));
	        System.out.println("Signature:" + encodedSignature);
	
	        sig.initVerify(publicKey);
	        sig.update(data);
	        byte[] sigBytesToVerify = Base64.getDecoder().decode(encodedSignature);
	        System.out.println(sig.verify(sigBytesToVerify));
        } catch (Exception e)
        {
        	e.printStackTrace();
        }
        
        /*
        String inputFileName = "/tmp/astrill-setup-mac.dmg";
        String outputFileName = "/tmp/astrill-setup-mac_enc.dmg";
        System.out.println("start encryption\n");
        keyManager.encryptFileWithSymmetricKey(myKey, inputFileName, outputFileName);
        System.out.println("done encryption\n");

        System.out.println("start decryption\n");
        String decryptedFileName = "/tmp/astrill-setup-mac_dec.dmg";
        keyManager.decryptFileWithSymmetricKey(myKey, outputFileName, decryptedFileName);
        System.out.println("done decryption\n");
        */
    }

}
