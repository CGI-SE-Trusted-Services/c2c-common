package org.certificateservices.custom.c2x.ecc;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

public class ECQV {
	
	private ECNamedCurveParameterSpec domainParameters;
	private MessageDigest  messageDigest;
	private SecureRandom secureRandom;
	private KeyPairGenerator keyPairGenerator;
	private KeyFactory keyFact;
	
	private KeyPair caKeys;
	
	public void setup(String curveName, String hashFunction) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException{
		domainParameters = ECNamedCurveTable.getParameterSpec(curveName);
		if(domainParameters == null){
			throw new NoSuchAlgorithmException("Error no domain parameters found for curve: " + curveName);
		}
		
		messageDigest = MessageDigest.getInstance(hashFunction, "BC");
		
		secureRandom = new SecureRandom();
		
		keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
		keyPairGenerator.initialize(domainParameters, secureRandom);
		
		caKeys = generateKeyPair();
		keyFact = KeyFactory.getInstance("EC", "BC");
		
	}
	
	public ECParameterSpec getDomainParameters(){
		return domainParameters;
	}
	
	public MessageDigest getMessageDigest(){
		return messageDigest;
	}
	
	public KeyPair generateKeyPair(){
		return keyPairGenerator.generateKeyPair();
	}
	
	public KeyPair getCAKeys(){
		return caKeys;
	}
	
	public CertReq genCertReq(PublicKey pk, byte[] U) throws InvalidKeyException{
		if(pk instanceof BCECPublicKey){
		   return new CertReq(((BCECPublicKey) pk).getQ().getEncoded(true), U);
		}
		throw new InvalidKeyException("Error invalid public key specificed when generating ECQV certificate request");
		
	}
	
	public CertResp genCertificate(CertReq certReq) throws InvalidKeySpecException, InvalidKeyException, IOException{

		//  3.4 Action 1  Decode RU
		BCECPublicKey Ru =  decodeECPublicKey(certReq.getRU());

		// 3.4 Action 2 Validate Ru
		validatePublicKey(Ru);

		ECPoint Pu = null;
		BigInteger e = null;
		KeyPair k_kG = null;
		byte[] certData = null;

		do{
			// 3.4 Action 3 Generate an EC key pair (k, kG)
			k_kG = keyPairGenerator.generateKeyPair();

			// 3.4 Action 4 	Compute the elliptic curve point Pu = Ru + kG
			Pu = Ru.getQ().add(((BCECPublicKey) k_kG.getPublic()).getQ());

			// 3.4 Action 5 Convert Pu to the octet string PU
			byte[] PU = Pu.getEncoded(true);

			// 3.4 Action 6 Create Certificate Structure
			MinimalFixedFieldCertificate cert = new MinimalFixedFieldCertificate(certReq.U, PU);

			certData = cert.getEncoded();
			// 3.4 Action 7 Compute Hash Modulo n
			e = computeHash(certData);

			// 3.4 Action 8 Check that e doesn't compute to infinity
		}while(Pu.multiply(e).add(((BCECPublicKey) caKeys.getPublic()).getQ()).isInfinity());

		// 3.4 Action 9 Compute the integer r
		BigInteger k = ((BCECPrivateKey) k_kG.getPrivate()).getD();
		BigInteger r = k.multiply(e).add(((BCECPrivateKey) caKeys.getPrivate()).getD()).mod(domainParameters.getN());

		return new CertResp(r, certData);
	}
	
	public BCECPublicKey extractPublicKey(byte[] certData, BCECPublicKey caPublicKey) throws IOException, InvalidKeySpecException, InvalidKeyException{
		return extractPublicKey(new MinimalFixedFieldCertificate(certData), certData, caPublicKey);
	}
	
	public BCECPublicKey extractPublicKey(MinimalFixedFieldCertificate cert, byte[] certData, BCECPublicKey caPublicKey) throws InvalidKeySpecException, InvalidKeyException{
		byte[] PU = cert.getPU();
		BCECPublicKey Pu = decodeECPublicKey(PU);
		
		if(!Pu.getQ().isValid()){
			throw new InvalidKeyException("Error Public Key is invalid");
		}
		
		BigInteger e = computeHash(certData);
		
		ECPoint Qu = Pu.getQ().multiply(e).add(caPublicKey.getQ());
		
		ECPublicKeySpec spec = new ECPublicKeySpec(Qu, domainParameters);
		BCECPublicKey retval =  (BCECPublicKey) keyFact.generatePublic(spec);
		
		return retval;
	}

	public BCECPrivateKey certReceiption(CertResp certResp, BCECPrivateKey Ku) throws InvalidKeyException, InvalidKeySpecException, IOException{
		BCECPublicKey Qu = extractPublicKey(certResp.getCertU(), (BCECPublicKey) caKeys.getPublic());
		
		BigInteger e = computeHash(certResp.getCertU());
		
		BigInteger Du = certResp.getR().add(e.multiply(Ku.getD())).mod(domainParameters.getN());
	
		if(!Qu.getQ().equals(domainParameters.getG().multiply(Du))){
			throw new InvalidKeyException("Invalid private key received");
		}
		
		ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(Du, domainParameters);
		BCECPrivateKey privateKey = (BCECPrivateKey) keyFact.generatePrivate(privateKeySpec);
		return privateKey;
	}
	
	public SelfSignedCertData genSelfCert(KeyPair keyPair, byte[] U) throws InvalidKeyException, InvalidKeySpecException, IOException{
		BCECPublicKey Pu = (BCECPublicKey) keyPair.getPublic();
		BCECPrivateKey Ku = (BCECPrivateKey) keyPair.getPrivate();
		
		byte[] PU = Pu.getQ().getEncoded(true);
		MinimalFixedFieldCertificate cert = new MinimalFixedFieldCertificate(U, PU);
		
		BigInteger e = computeHash(cert.getEncoded());
		
		BigInteger Du = Ku.getD().multiply(e).mod(domainParameters.getN());
		
		
		ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(Du, domainParameters);
		BCECPrivateKey privateKey = (BCECPrivateKey) keyFact.generatePrivate(privateKeySpec);
		
		return new SelfSignedCertData(cert, privateKey);
	}
	
	public BCECPublicKey extractSelfCertKey(byte[] selfSignedCert) throws IOException, InvalidKeySpecException, InvalidKeyException{
		MinimalFixedFieldCertificate cert = new MinimalFixedFieldCertificate(selfSignedCert);
		
		byte[] PU = cert.getPU();
		
		BCECPublicKey Pu = decodeECPublicKey(PU);
		
		if(!Pu.getQ().isValid()){
			throw new InvalidKeyException("Error Public Key is invalid");
		}
		
		BigInteger e = computeHash(selfSignedCert);
		
		ECPoint Qu = Pu.getQ().multiply(e);
		
		ECPublicKeySpec spec = new ECPublicKeySpec(Qu, domainParameters);
		return (BCECPublicKey) keyFact.generatePublic(spec);
	}
	
	
	
	private BigInteger computeHash(byte[] certData) {
		byte[] h = messageDigest.digest(certData);
		int fieldSize = domainParameters.getCurve().getFieldSize()/8;
		byte[] E = new byte[fieldSize];
		ByteBuffer bb = ByteBuffer.wrap(E);
		if(h.length > fieldSize ){
			bb.put(h,0,fieldSize);
		}else{
			bb.put(h, fieldSize - h.length, h.length);
		}
		
		return new BigInteger(1, E);
	}

	private BCECPublicKey decodeECPublicKey(byte[] encodedPublicKey) throws InvalidKeySpecException{
		ECPoint eCPoint = domainParameters.getCurve().decodePoint(encodedPublicKey);
		ECPublicKeySpec spec = new ECPublicKeySpec(eCPoint, domainParameters);
		BCECPublicKey publicKey =  (BCECPublicKey) keyFact.generatePublic(spec);
		
		return publicKey;
	}
	
	private void validatePublicKey(BCECPublicKey pk) throws InvalidKeyException{
		if(!pk.getQ().isValid()){
			throw new InvalidKeyException("Error EC public key was invalid.");
		}
	}
	
	public class CertResp{
		
		BigInteger r;
		byte[] certU;
		
		public CertResp(BigInteger r, byte[] certU) {
			super();
			this.r = r;
			this.certU = certU;
		}
		
		public BigInteger getR() {
			return r;
		}
		public byte[] getCertU() {
			return certU;
		}
		
	}
	
	
	public class CertReq{
		byte[] RU;
		byte[] U;
		
		
		
		public CertReq(byte[] RU, byte[] U) {
			super();
			this.RU = RU;
			this.U = U;
		}
		public byte[] getRU() {
			return RU;
		}
		public byte[] getU() {
			return U;
		}
	}


	public class SelfSignedCertData{
		MinimalFixedFieldCertificate cert;
		BCECPrivateKey privateKey;
		
		
		
		public SelfSignedCertData(MinimalFixedFieldCertificate cert,
				BCECPrivateKey privateKey) {
			super();
			this.cert = cert;
			this.privateKey = privateKey;
		}
		
		public MinimalFixedFieldCertificate getCert() {
			return cert;
		}
		public BCECPrivateKey getPrivateKey() {
			return privateKey;
		}
		
		
	}
}
