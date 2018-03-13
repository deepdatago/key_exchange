package key_exchange;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;


public class KeyManagerImpl implements KeyManager {
	private final String algorithm; // "RSA"
	private final int keySize; // 4096
	private final int certExpireInDays; // 365
	private final String signatureAlg; // signatureAlgorithm "SHA256withRSA"
	private final String privateKeyDescription = "RSA PRIVATE KEY";
	private final String certificateDescription = "CERTIFICATE";
	private final String providerName = "BC"; // for bouncy castle
	private final String commonName; // "CN=KeyManagerTest"
	public KeyManagerImpl(String algorithm, 
			String signatureAlg, 
			int keySize, 
			int certExpireInDays, 
			String commonName) {
		this.algorithm = algorithm;
		this.keySize = keySize;
		this.signatureAlg = signatureAlg;
		this.certExpireInDays = certExpireInDays;
		this.commonName = commonName;
    	Security.addProvider(new BouncyCastleProvider());
    	fixAESKeyLength();
	}
	public KeyManagerImpl() {
		this.algorithm = "RSA";
		this.keySize = 4096;
		this.signatureAlg = "SHA256withRSA";
		this.certExpireInDays = 365;
		this.commonName = "CN=KeyManagerTest";
    	Security.addProvider(new BouncyCastleProvider());
    	fixAESKeyLength();
	}
	public void generateKeyCertificate(String privKeyFileName, String certFileName) {
    	KeyPair keyPair;
    	PrivateKey privateKey;
    	// PublicKey publicKey;
    	
		try {
			keyPair = generateKeyPair(this.algorithm, this.keySize);
			privateKey = keyPair.getPrivate();
			writePemFile(privateKey.getEncoded(), this.privateKeyDescription, privKeyFileName);
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return;
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
		
    	ContentSigner sigGen;
		try {
			sigGen = new JcaContentSignerBuilder(this.signatureAlg).setProvider(this.providerName).build(privateKey);
		} catch (OperatorCreationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		} 

    	SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
    	 
    	Date startDate = new Date(System.currentTimeMillis());
    	Date endDate = new Date(System.currentTimeMillis() + this.certExpireInDays * 24 * 60 * 60 * 1000);
    	 
    	X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(
    	          new X500Name(this.commonName),
    	          BigInteger.ONE,
    	          startDate, endDate,
    	          new X500Name(this.commonName),
    	          subPubKeyInfo);
    	     
    	X509CertificateHolder certHolder = v1CertGen.build(sigGen); 
    	X509Certificate certificate;
		try {
			certificate = new JcaX509CertificateConverter().setProvider(this.providerName)
				  .getCertificate( certHolder );
	    	writePemFile(certificate.getEncoded(), this.certificateDescription, certFileName);		
		} catch (CertificateException e) {
			e.printStackTrace();
			return;
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	public PublicKey loadPublicKeyFromRSA_X509_CertificatePEM(String fileName)
			throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
    	X509Certificate certificate = null;
    	String instanceName = "X.509";

    	try {
        	CertificateFactory certFactory = null;
			certFactory= CertificateFactory
					  .getInstance(instanceName, this.providerName);
			certificate = (X509Certificate) certFactory
					  .generateCertificate(new FileInputStream(fileName));
			
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
    	
    	return certificate.getPublicKey();
    }

    public PrivateKey loadPrivateKeyFromRSAPEM(String fileName) 
    		throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
    	String instanceName = "RSA";
    	PEMParser pemParser = null;
		File privateKeyFile = new File(fileName);
		pemParser = new PEMParser(new FileReader(privateKeyFile));
		PemObject pemObject = pemParser.readPemObject();
    	KeyFactory factory = KeyFactory.getInstance(instanceName, this.providerName);
    	byte[] content = pemObject.getContent();
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
		pemParser.close();
		try {
			return factory.generatePrivate(privKeySpec);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	   
		return null;
    }   	
    
    public String encryptTextBase64(byte[] text, PublicKey key) throws Exception
    {
        byte[] cipherText = null;
        //
        // get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text);
        return new String(Base64.getEncoder().encode(cipherText));
    }    
    
    public String decryptTextBase64(byte[] text, PrivateKey key) throws Exception
    {
    	byte[] decodedBytes = Base64.getDecoder().decode(text);
        byte[] dectyptedText = null;
        // decrypt the text using the private key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        dectyptedText = cipher.doFinal(decodedBytes);
        return new String(dectyptedText);

    }
    
    private void writePemFile(byte[] encodedBytes, String description, String filename) throws IOException {
    	PemObject pemObject = new PemObject(description, encodedBytes);
		PemWriter pemWriter = null;
		pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)));
		pemWriter.writeObject(pemObject);
		pemWriter.close();
	}
	private KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
		keyGen.initialize(keySize);
		return keyGen.genKeyPair();
	}
	
    public static void fixAESKeyLength() {
        String errorString = "Failed manually overriding key-length permissions.";
        int newMaxKeyLength;
        try {
            if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES")) < 256) {
                Class c = Class.forName("javax.crypto.CryptoAllPermissionCollection");
                Constructor con = c.getDeclaredConstructor(null);
                con.setAccessible(true);
                Object allPermissionCollection = con.newInstance(null);
                Field f = c.getDeclaredField("all_allowed");
                f.setAccessible(true);
                f.setBoolean(allPermissionCollection, true);

                c = Class.forName("javax.crypto.CryptoPermissions");
                con = c.getDeclaredConstructor(null);
                con.setAccessible(true);
                Object allPermissions = con.newInstance(null);
                f = c.getDeclaredField("perms");
                f.setAccessible(true);
                ((Map) f.get(allPermissions)).put("*", allPermissionCollection);

                c = Class.forName("javax.crypto.JceSecurityManager");
                f = c.getDeclaredField("defaultPolicy");
                f.setAccessible(true);
                Field mf = Field.class.getDeclaredField("modifiers");
                mf.setAccessible(true);
                mf.setInt(f, f.getModifiers() & ~Modifier.FINAL);
                f.set(null, allPermissions);

                newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            }
        } catch (Exception e) {
            throw new RuntimeException(errorString, e);
        }
        if (newMaxKeyLength < 256)
            throw new RuntimeException(errorString); // hack failed
    }	
}
