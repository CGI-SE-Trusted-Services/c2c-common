package org.certificateservices.custom.c2x.ecc

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security;
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream

import org.bouncycastle.crypto.tls.CertificateURL;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.ecc.ECQV.CertReq;
import org.certificateservices.custom.c2x.ecc.ECQV.CertResp;
import org.certificateservices.custom.c2x.ecc.ECQV.SelfSignedCertData;

import spock.lang.Specification;
import spock.lang.Unroll;

class ECQVSpec extends Specification{

	ECQV ecqv = new ECQV();

	def setupSpec(){
		if(Security.getProvider("BC") == null){
			Security.addProvider(new BouncyCastleProvider());
		 }
	}
	
	def "Verify setup TODO"(){
		when:
		ecqv.setup("P-256", "SHA256")
		
		then:
		ecqv.domainParameters.getCurve().getFieldSize() != null
		ecqv.domainParameters.getCurve().getA() != null
		ecqv.domainParameters.getCurve().getB() != null
		ecqv.domainParameters.getG() != null
		ecqv.domainParameters.getH() != null
		ecqv.domainParameters.getN() != null
		
		ecqv.getMessageDigest() != null
	}
	
	def "Verify generate key pair"(){
		setup:
		ecqv.setup("P-256", "SHA256")
		when:
		KeyPair kp = ecqv.generateKeyPair()
		PrivateKey privKey = kp.getPrivate();
		PublicKey pubKey = kp.getPublic();
		then:
		privKey instanceof BCECPrivateKey
		privKey.getD() != null
		pubKey instanceof BCECPublicKey
		
		pubKey.getQ() != null
		pubKey.getQ().encoded
		
	}
	
	def "Verify CA Keys"(){
		setup:
		ecqv.setup("P-256", "SHA256")
		expect:
		ecqv.getCAKeys() != null
	}
	
	def "Verify genCertReq"(){
		setup:
		ecqv.setup("P-256", "SHA256")
		KeyPair kp = ecqv.generateKeyPair()
		when:
		CertReq cr = ecqv.genCertReq(kp.getPublic(), "SomeU".getBytes("UTF-8"))
		then:
		cr.getRU() != null
		new String(cr.getU(),"UTF-8") == "SomeU"
	}
	
	def "Verify genCertificate"(){
		setup:
		ecqv.setup("P-256", "SHA256")
		KeyPair kp = ecqv.generateKeyPair()
		CertReq cr = ecqv.genCertReq(kp.getPublic(), "SomeU".getBytes("UTF-8"))
		when:
		CertResp  certResp = ecqv.genCertificate(cr)
		
		then:
		certResp.getCertU() != null
		certResp.getR() != null; 
	}
	
	def "Verify extractPublicKey"(){
		setup:
		ecqv.setup("P-256", "SHA256")
		KeyPair kp = ecqv.generateKeyPair()
		CertReq cr = ecqv.genCertReq(kp.getPublic(), "SomeU".getBytes("UTF-8"))
		CertResp  certResp = ecqv.genCertificate(cr)
		when:
		BCECPublicKey publicKey = ecqv.extractPublicKey(certResp.certU, ecqv.getCAKeys().getPublic())
		
		then:
		publicKey.getQ().isValid()
		

	}
	
	def "Verify certReceiption"(){
		setup:
		ecqv.setup("P-256", "SHA256")
		KeyPair kp = ecqv.generateKeyPair()
		CertReq cr = ecqv.genCertReq(kp.getPublic(), "SomeU".getBytes("UTF-8"))
		CertResp  certResp = ecqv.genCertificate(cr)
		
		when:
		PrivateKey privKey = ecqv.certReceiption(certResp, kp.getPrivate())
		PublicKey pubKey = ecqv.extractPublicKey(certResp.certU, ecqv.getCAKeys().getPublic())
		
		then:
	    privKey != null
		pubKey != null
			
		when:
		byte[] clearText = "SomeClearTextData".getBytes("UTF-8")
		byte[] encrytedText = encryptData(clearText, pubKey)
		byte[] decryptedText = decryptData(encrytedText, privKey)
		
		then:
		clearText != encrytedText
		clearText == decryptedText;
		
		when:
		byte[] signData = "SomeSignData".getBytes("UTF-8")
		byte[] signature = signDataECDSA(signData, privKey)
		
		then:
		verifySignedDataECDSA(signData, signature, pubKey)
		
	}
	
	def "Verify genSelfCert and extractSelfCertPublicKey"(){
		setup:
		ecqv.setup("P-256", "SHA256")
		KeyPair kp = ecqv.generateKeyPair()
		when:
		
		SelfSignedCertData selfSignedCertData = ecqv.genSelfCert(kp, "SomeU".getBytes("UTF-8"))
		
		then:
		selfSignedCertData.getCert() != null;
		selfSignedCertData.getPrivateKey() != null;
		
		when:
		
		byte[] selfSignedCert = selfSignedCertData.cert.getEncoded();
		
		BCECPrivateKey selfSignedPrivate = selfSignedCertData.privateKey;
		
		BCECPublicKey selfSignedPublic = ecqv.extractSelfCertKey(selfSignedCert);
		
		then:
		selfSignedPublic != null
		
		when:
		
		// Try to encrypt and decrypt
		byte[] clearText = "SomeClearTextData".getBytes("UTF-8")
		
		byte[] encrytedText = encryptData(clearText, selfSignedPublic)
		
		byte[] decryptedText = decryptData(encrytedText, selfSignedPrivate)
		
		then:
		clearText != encrytedText
		clearText == decryptedText;
		
		when:
		
		byte[] signData = "SomeSignData".getBytes("UTF-8")
		byte[] signature = signDataECDSA(signData, selfSignedPrivate)
		
		then:
		verifySignedDataECDSA(signData, signature, selfSignedPublic)
		
	}
	
	
	private byte[] signDataECDSA(byte[] data, PrivateKey privKey){
		Signature ecdsa = Signature.getInstance("SHA256withECDSA");
		
		ecdsa.initSign(privKey)
		
		ecdsa.update(data)
		
		return ecdsa.sign()
	}
	
	private boolean verifySignedDataECDSA(byte[] data, byte[] signature, PublicKey pk){
		Signature ecdsa = Signature.getInstance("SHA256withECDSA");
		ecdsa.initVerify(pk);
		
		ecdsa.update(data)

		return ecdsa.verify(signature)		
	}
	
	private byte[] encryptData(byte[] data, PublicKey pk){
		Cipher cipher = Cipher.getInstance("ECIES", "BC");
		
		IESParameterSpec iesParams = new IESParameterSpec(null, null, 128);
		cipher.init(Cipher.ENCRYPT_MODE, pk, iesParams);
		
		byte[] block = new byte[64];
		ByteArrayInputStream bais = new ByteArrayInputStream(data);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		CipherOutputStream cos = new CipherOutputStream(baos, cipher);
		
		int i;
		while ((i = bais.read(block)) != -1) {
		  cos.write(block, 0, i);
		}
		cos.close();
		
		return baos.toByteArray()
	}
	
	private byte[] decryptData(byte[] encryptedData, PrivateKey privKey){
		Cipher cipher = Cipher.getInstance("ECIES", "BC");
		
		IESParameterSpec iesParams = new IESParameterSpec(null, null, 128);
		cipher.init(Cipher.DECRYPT_MODE, privKey, iesParams);
		
		ByteArrayInputStream bais = new ByteArrayInputStream(encryptedData);
		
		byte[] block = new byte[64];
		CipherInputStream cis = new CipherInputStream(bais, cipher);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		int i;
		while ((i = cis.read(block)) != -1) {
		  baos.write(block, 0, i);
		 }
		baos.close();
		
		return baos.toByteArray()
		
	}
	
}
