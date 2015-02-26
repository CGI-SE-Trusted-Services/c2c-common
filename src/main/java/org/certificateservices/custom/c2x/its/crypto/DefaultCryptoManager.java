/************************************************************************
*                                                                       *
*  Certificate Service -  Car2Car Core                                  *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.custom.c2x.its.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIES;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.certificateservices.custom.c2x.its.datastructs.SerializationHelper;
import org.certificateservices.custom.c2x.its.datastructs.StructSerializer;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.EcdsaSignature;
import org.certificateservices.custom.c2x.its.datastructs.basic.EncryptionParameters;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;
import org.certificateservices.custom.c2x.its.datastructs.basic.SymmetricAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttribute;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType;
import org.certificateservices.custom.c2x.its.datastructs.msg.EciesNistP256EncryptedKey;
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderField;
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderFieldType;
import org.certificateservices.custom.c2x.its.datastructs.msg.Payload;
import org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType;
import org.certificateservices.custom.c2x.its.datastructs.msg.RecipientInfo;
import org.certificateservices.custom.c2x.its.datastructs.msg.SecuredMessage;
import org.certificateservices.custom.c2x.its.datastructs.msg.TrailerField;
import org.certificateservices.custom.c2x.its.datastructs.msg.TrailerFieldType;

/**
 * Default implementation of ITS CryptoManager with support for public key algorithms: ecdsa_nistp256_with_sha256 and ecies_nistp256
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class DefaultCryptoManager implements CryptoManager {
	
   
	protected ECParameterSpec ecNistP256Spec = ECNamedCurveTable.getParameterSpec("P-256");
	protected KeyPairGenerator ecNistP256Generator;
	protected KeyGenerator aES128Generator;
	protected SecureRandom secureRandom = new SecureRandom();
	protected SecP256R1Curve ecNistP256Curve = new SecP256R1Curve();
	protected KeyFactory keyFact;
	protected MessageDigest sha256Digest;
	
	protected String provider;
	
	// dummy signatures used to generate signature sizes 
	protected static HashMap<PublicKeyAlgorithm, Signature> dummySignatures = new HashMap<PublicKeyAlgorithm, Signature>();
	static{
		dummySignatures.put(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new Signature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger("0")), new byte[PublicKeyAlgorithm.ecdsa_nistp256_with_sha256.getFieldSize()])));
	}

	/**
	 * Initialized Bouncycastle and it's specific key factories
	 */
	@Override
	public void setupAndConnect(CryptoManagerParams params) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, IOException, BadCredentialsException{
		if(!(params instanceof DefaultCryptoManagerParams)){
			throw new IllegalArgumentException("Invalid type of CryptoManagerParams given, expected DefaultCryptoManagerParams");
		}
		provider = ((DefaultCryptoManagerParams) params).getProvider();
		
		
		try{
			if(Security.getProvider("BC") == null){
			  Security.addProvider(new BouncyCastleProvider());
			}
			ecNistP256Generator = KeyPairGenerator.getInstance("ECDSA", provider);
			ecNistP256Generator.initialize(ecNistP256Spec, secureRandom);
			sha256Digest = MessageDigest.getInstance("SHA-256","BC");
			keyFact = KeyFactory.getInstance("ECDSA", "BC");
			aES128Generator = KeyGenerator.getInstance("AES","BC");
			aES128Generator.init(128);
			
			
		}catch(InvalidAlgorithmParameterException e){
			throw new NoSuchAlgorithmException("InvalidAlgorithmParameterException: " + e.getMessage(),e);
		}
	}
	
	/**
	 *  @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#encryptSecureMessage(SecuredMessage, PublicKeyAlgorithm, List)
	 */
	public SecuredMessage encryptSecureMessage(SecuredMessage secureMessage, PublicKeyAlgorithm encryptionAlg, List<Certificate> receipients) throws  IllegalArgumentException, GeneralSecurityException, IOException{
		return encryptSecureMessage(secureMessage, encryptionAlg, receipients, PayloadType.encrypted);
	}
	

	protected SecuredMessage encryptSecureMessage(SecuredMessage secureMessage, PublicKeyAlgorithm encryptionAlg, List<Certificate> receipients, PayloadType payloadType) throws  IllegalArgumentException, GeneralSecurityException, IOException{
		
		if(receipients == null || receipients.size() == 0){
			throw new IllegalArgumentException("Error encrypting message list of receipients cannot be empty");
		}
		
		if(encryptionAlg != PublicKeyAlgorithm.ecies_nistp256){
			throw new IllegalArgumentException("Error unsupported encryption algorithm: " + encryptionAlg);
		}
		
		secureMessage = new SecuredMessage(secureMessage.getEncoded()); // Make sure to return a clone of the input message.
		
		byte[] nounce = new byte[12];
		secureRandom.nextBytes(nounce);
		EncryptionParameters encParams = new EncryptionParameters(encryptionAlg.getRelatedSymmetricAlgorithm(), nounce);
		
		Key symmetricKey = aES128Generator.generateKey();
		List<StructSerializer> reciptientInfos = new ArrayList<StructSerializer>();
		// Verify that all certificates have encryption keys
		for(Certificate c : receipients){
			org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey encKey = getEncryptionKey(c);
			PublicKey encryptionKey = (PublicKey) decodeEccPoint(encKey.getPublicKeyAlgorithm(), encKey.getPublicKey());
			HashedId8 certHash = new HashedId8(c.getEncoded());
			EciesNistP256EncryptedKey encryptedKey = eCEISEncryptSymmetricKey(encryptionAlg, encryptionKey, symmetricKey);
			reciptientInfos.add(new RecipientInfo(certHash, encryptedKey));
		}
		
		addHeader(secureMessage, new HeaderField(HeaderFieldType.recipient_info, reciptientInfos));
		addHeader(secureMessage,new HeaderField(encParams));
		
		for(Payload payload : secureMessage.getPayloadFields()){
			if(payload.getPayloadType() == payloadType){
			   payload.setData(symmetricEncrypt(encryptionAlg.getRelatedSymmetricAlgorithm(), payload.getData(), symmetricKey, nounce));
			}
		}

		return secureMessage;
	}
	

	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#signAndEncryptSecureMessage(SecuredMessage, Certificate, SignerInfoType, PublicKeyAlgorithm, PrivateKey, PublicKeyAlgorithm, List)
	 */
	@Override
	public SecuredMessage encryptAndSignSecureMessage(
			SecuredMessage secureMessage, Certificate signerCertificate,
			SignerInfoType signInfoType, PublicKeyAlgorithm signAlg,
			PrivateKey signPrivateKey, PublicKeyAlgorithm encryptionAlg,
			List<Certificate> receipients) throws IllegalArgumentException,
			GeneralSecurityException, IOException {
		SecuredMessage encryptedMessage = encryptSecureMessage(secureMessage, encryptionAlg, receipients, PayloadType.signed_and_encrypted);
		return signSecureMessage(encryptedMessage, signerCertificate, signInfoType, signAlg, signPrivateKey);
	}

	
	/**
	 *  @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#decryptSecureMessage(SecuredMessage, Certificate, PrivateKey)
	 */
	public SecuredMessage decryptSecureMessage(SecuredMessage secureMessage, Certificate receiverCertificate, PrivateKey receiverKey) throws  IllegalArgumentException, GeneralSecurityException, IOException{
	  return decryptSecureMessage(secureMessage, receiverCertificate, receiverKey, PayloadType.encrypted);
	}
	

	protected SecuredMessage decryptSecureMessage(SecuredMessage secureMessage, Certificate receiverCertificate, PrivateKey receiverKey, PayloadType payloadType) throws  IllegalArgumentException, GeneralSecurityException, IOException{
		
	  secureMessage = new SecuredMessage(secureMessage.getEncoded()); // Make sure to return a clone of the input message.
	  EncryptionParameters encParams = findHeader(secureMessage, HeaderFieldType.encryption_parameters, true).getEncParams(); 
	  RecipientInfo receipentInfo = findRecipientInfo(receiverCertificate, findHeader(secureMessage, HeaderFieldType.recipient_info, true).getRecipients());
	  Key symmetricKey = eCEISDecryptSymmetricKey(receipentInfo.getPkEncryption(), receiverKey);
	
	  for(Payload payload : secureMessage.getPayloadFields()){
			if(payload.getPayloadType() == payloadType){
			   payload.setData(symmetricDecrypt(receipentInfo.getPublicKeyAlgorithm().getRelatedSymmetricAlgorithm(), payload.getData(), symmetricKey, encParams.getNounce()));
			}
		}

	  return secureMessage;
	}	
	
	

	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#signSecureMessage(SecuredMessage, Certificate, SignerInfoType, PublicKeyAlgorithm, PrivateKey)
	 */
	@Override
	public SecuredMessage signSecureMessage(SecuredMessage secureMessage, Certificate signerCertificate, SignerInfoType signerInfoType, PublicKeyAlgorithm alg,
			PrivateKey privateKey) throws IllegalArgumentException, SignatureException, IOException {	
		
        if(signerInfoType == SignerInfoType.certificate){
            addHeader(secureMessage,new HeaderField(new SignerInfo(signerCertificate)));
        }else{        	
			try {
				HashedId8 hash = new HashedId8(digest(signerCertificate.getEncoded(), PublicKeyAlgorithm.ecdsa_nistp256_with_sha256));
				addHeader(secureMessage,new HeaderField(new SignerInfo(hash)));
			} catch (NoSuchAlgorithmException e) {
				throw new SignatureException("Error generating secured message, no such algorithm: " + e.getMessage(),e);
			}		
        }
		
		Signature dummySignature =  dummySignatures.get(alg);
		byte[] toBeSigned = serializeDataToBeSignedInSecuredMessage(secureMessage, dummySignature);
		Signature signature = signMessage(toBeSigned, alg, privateKey);
		secureMessage.attachSignature(signature);
		return secureMessage;
	}


	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#signMessage(byte[], PublicKeyAlgorithm,  PrivateKey)
	 */
	@Override
	public Signature signMessage(byte[] message, PublicKeyAlgorithm alg,
			PrivateKey privateKey)
			throws IllegalArgumentException, SignatureException, IOException {		
		
		ASN1InputStream asn1InputStream = null;
		try{
			byte[] messageDigest = digest(message, alg);

			java.security.Signature signature = java.security.Signature.getInstance("NONEwithECDSA", provider); 
			signature.initSign(privateKey);
			signature.update(messageDigest);
			byte[] dERSignature = signature.sign();


			ByteArrayInputStream inStream = new ByteArrayInputStream(dERSignature);
			asn1InputStream = new ASN1InputStream(inStream);

			DLSequence dLSequence = (DLSequence) asn1InputStream.readObject();
			BigInteger r = ((ASN1Integer) dLSequence.getObjectAt(0)).getPositiveValue();
			BigInteger s = ((ASN1Integer) dLSequence.getObjectAt(1)).getPositiveValue();

			ByteArrayOutputStream baos = new ByteArrayOutputStream(alg.getFieldSize());
			SerializationHelper.writeFixedFieldSizeKey(alg, baos, s);	    

			return new Signature(alg, new EcdsaSignature(alg, new EccPoint(alg, EccPointType.x_coordinate_only, r), baos.toByteArray()));

		}catch(Exception e){
			if(e instanceof IllegalArgumentException){
				throw (IllegalArgumentException) e;
			}
			if(e instanceof IOException){
				throw (IOException) e;
			}
			if(e instanceof SignatureException){
				throw (SignatureException) e;
			}
			
			throw new SignatureException("Internal error generating signature " + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
			
		}finally{
			if(asn1InputStream != null){
				asn1InputStream.close();
			}			
		}
	}

	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifySignature(byte[], Signature, EccPoint)
	 */
	@Override
	public boolean verifySignature(byte[] message, Signature signature,
			EccPoint publicKey) throws IllegalArgumentException,
			SignatureException, IOException {
		if(publicKey.getEccPointType() == EccPointType.x_coordinate_only){
			throw new IllegalArgumentException("Error, public key with x_coordinate only isn't supported when verifing signature");
		}

		PublicKey pubKey;
		try {
			pubKey = (PublicKey) decodeEccPoint(signature.getPublicKeyAlgorithm(), publicKey);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException("Illegal key format when decoding EccPoint key: " + e.getMessage(), e);
		}
		
		return verifySignature(message, signature, pubKey);
	}

	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifySignature(byte[], Signature, PublicKey)
	 */
	@Override
	public boolean verifySignature(byte[] message, Signature signature,
			PublicKey publicKey) throws IllegalArgumentException,
			SignatureException, IOException {
		PublicKeyAlgorithm alg = signature.getPublicKeyAlgorithm();
		
		if(alg ==PublicKeyAlgorithm.ecdsa_nistp256_with_sha256){
			try{
				EcdsaSignature ecdsaSignature = signature.getSignatureValue();

				// Create Signature Data
				ASN1Integer asn1R = new ASN1Integer(ecdsaSignature.getR().getX());		    
				ASN1Integer asn1S = new ASN1Integer(SerializationHelper.readFixedFieldSizeKey(alg, new ByteArrayInputStream(ecdsaSignature.getSignatureValue())));
				DLSequence dLSequence = new DLSequence(new ASN1Encodable[]{asn1R, asn1S});
				byte[] dERSignature = dLSequence.getEncoded();

				byte[] messageDigest = digest(message, alg);

				java.security.Signature sig = java.security.Signature.getInstance("NONEwithECDSA", provider); 
				sig.initVerify(publicKey);
				sig.update(messageDigest);
				return sig.verify(dERSignature);
			}catch(Exception e){
				if(e instanceof IllegalArgumentException){
					throw (IllegalArgumentException) e;
				}
				if(e instanceof IOException){
					throw (IOException) e;
				}
				if(e instanceof SignatureException){
					throw (SignatureException) e;
				}
				
				throw new SignatureException("Internal error verifying signature " + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
			}
		
		}else{
			throw new IllegalArgumentException("Unsupported signature algoritm: " + signature.getPublicKeyAlgorithm());
		}
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifySignature(byte[], Signature, Certificate)
	 */
	@Override
	public boolean verifySignature(byte[] message, Signature signature, Certificate signerCert) throws IllegalArgumentException,  SignatureException, IOException{
		return verifySignature(message, signature, getVerificationKey(signerCert));
	}
	

	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifyCertificate(Certificate)
	 */
	@Override
	public boolean verifyCertificate(Certificate certificate) throws IllegalArgumentException,  SignatureException, IOException{
		SignerInfo si = findFirstValidSignerInfo(certificate);
		switch(si.getSignerInfoType()){
		case self:
			return verifyCertificate(certificate, certificate);
		case certificate:
			return verifyCertificate(certificate, si.getCertificate());
		case certificate_chain:
			return verifyCertificate(certificate, si.getCertificateChain().get(si.getCertificateChain().size() -1));
		default:
			throw new IllegalArgumentException("No signer info of type self, certificate or certificate_chain found when verifying certificate");
		}
	}



	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifyCertificate(Certificate, EccPoint)
	 */
	@Override
	public boolean verifyCertificate(Certificate certificate, EccPoint publicKey) throws IllegalArgumentException,  SignatureException, IOException{
		byte[] certData = serializeCertWithoutSignature(certificate);
		return verifySignature(certData, certificate.getSignature(), publicKey);
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifyCertificate(Certificate,  PublicKey)
	 */
	@Override
	public boolean verifyCertificate(Certificate certificate, PublicKey publicKey) throws IllegalArgumentException,  SignatureException, IOException{
		byte[] certData = serializeCertWithoutSignature(certificate);
		return verifySignature(certData, certificate.getSignature(), publicKey);
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifyCertificate(Certificate,  Certificate)
	 */
	@Override
	public boolean verifyCertificate(Certificate certificate, Certificate signerCert) throws IllegalArgumentException,  SignatureException, IOException{
		byte[] certData = serializeCertWithoutSignature(certificate);
		return verifySignature(certData, certificate.getSignature(), signerCert);
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifySecuredMessage(SecuredMessage)
	 */
	@Override
	public void verifySecuredMessage(SecuredMessage message)
			throws IllegalArgumentException, InvalidITSSignatureException, SignatureException, IOException {
		Certificate signerCert = findFirstValidCertificateInMessage(message);
		verifySecuredMessage(message, signerCert);
	}

	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifySecuredMessage(SecuredMessage, Certificate)
	 */
	@Override
	public void verifySecuredMessage(SecuredMessage message,
			Certificate signerCert) throws IllegalArgumentException, InvalidITSSignatureException,
			SignatureException, IOException {
		Signature signature = findSignatureInMessage(message);
		byte[] msgData = serializeDataToBeSignedInSecuredMessage(message, signature);
	
		if(!verifySignature(msgData, signature, signerCert)){
			throw new InvalidITSSignatureException("Error verifying signature of SecuredMessage");
		}
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifyAndDecryptSecuredMessage(SecuredMessage, Certificate, PrivateKey)
	 */
	@Override
	public SecuredMessage verifyAndDecryptSecuredMessage(
			SecuredMessage message, Certificate receiverCertificate,
			PrivateKey receiverKey) throws IllegalArgumentException, InvalidITSSignatureException, GeneralSecurityException, IOException{
		verifySecuredMessage(message);
		return decryptSecureMessage(message, receiverCertificate, receiverKey, PayloadType.signed_and_encrypted);
	}

	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifyAndDecryptSecuredMessage(SecuredMessage, Certificate, Certificate, PrivateKey)
	 */
	@Override
	public SecuredMessage verifyAndDecryptSecuredMessage(
			SecuredMessage message, Certificate signerCert,
			Certificate receiverCertificate, PrivateKey receiverKey)
			throws IllegalArgumentException, InvalidITSSignatureException, GeneralSecurityException, IOException{
		verifySecuredMessage(message, signerCert);
		return decryptSecureMessage(message, receiverCertificate, receiverKey, PayloadType.signed_and_encrypted);
	}

	/**
	 * Supports ECDSA P256
	 * 
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#generateKeyPair(PublicKeyAlgorithm)
	 */
	public KeyPair generateKeyPair(PublicKeyAlgorithm alg){
		if(alg == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256 || alg == PublicKeyAlgorithm.ecies_nistp256){
			return ecNistP256Generator.generateKeyPair();
		}
		return null;
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#encodeEccPoint(PublicKeyAlgorithm, EccPointType, PublicKey)
	 */
	public EccPoint encodeEccPoint(PublicKeyAlgorithm alg, EccPointType type, PublicKey publicKey) throws IllegalArgumentException, InvalidKeySpecException{
		if(! (publicKey instanceof java.security.interfaces.ECPublicKey)){
			throw new IllegalArgumentException("Only ec public keys are supported, not " + publicKey.getClass().getSimpleName());
		}
		BCECPublicKey bcPub = convertECPublicKeyToBCECPublicKey(alg, (java.security.interfaces.ECPublicKey) publicKey);

		if(type == EccPointType.uncompressed){
			return new EccPoint(alg, type, bcPub.getW().getAffineX(), bcPub.getW().getAffineY());
		}
		if(type == EccPointType.compressed_lsb_y_0 || type == EccPointType.compressed_lsb_y_1){			
			return new EccPoint(alg, bcPub.getQ().getEncoded(true));            
		}
		if(type == EccPointType.x_coordinate_only){
			return new EccPoint(alg, type, bcPub.getW().getAffineX());
		}

		throw new IllegalArgumentException("Unsupported ecc point type: " + type);
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#decodeEccPoint(PublicKeyAlgorithm, EccPoint)
	 */
	public Object decodeEccPoint(PublicKeyAlgorithm alg, EccPoint point) throws InvalidKeySpecException{
		switch(point.getEccPointType()){
		case x_coordinate_only:
		    return point.getX();			
		case compressed_lsb_y_0:
		case compressed_lsb_y_1:			
			return getECPublicKeyFromECPoint(alg, getECCurve(alg).decodePoint(point.getCompressedEncoding()));
		case uncompressed:
			return getECPublicKeyFromECPoint(alg, getECCurve(alg).createPoint(point.getX(), point.getY()));
		}
		return null;
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#digest(byte[], PublicKeyAlgorithm)
	 */
	public byte[] digest(byte[] message, PublicKeyAlgorithm alg) throws IllegalArgumentException, NoSuchAlgorithmException {
		if(alg == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256){
            sha256Digest.update(message); 
			return sha256Digest.digest();
		}else{
			throw new IllegalArgumentException("Unsupported signature algorithm: " + alg);
		}
	}
	
	protected final int ECIES_NIST_P256_V_LENGTH = 65;
	
	/**
	 * Help method to perform a ECIES encryption to a recipient of a symmetric key. 
	 * 
	 * @param publicKeyAlgorithm the algorithm used.
	 * @param encryptionKey the public encryption key of the recipient
	 * @param symmetricKey the symmetric key to encrypt
	 * @return a EciesNistP256EncryptedKey to be included in a SecureMessage header.
	 * 
	 * @throws InvalidKeyException if supplied key was corrupt.
	 * @throws InvalidAlgorithmParameterException if algorithm was badly specified.
	 * @throws IllegalBlockSizeException if encrypted data was corrupt.
	 * @throws BadPaddingException if encrypted data was corrupt.
	 * @throws IllegalArgumentException if arguments where invalid or algorithm not supported.
	 * @throws InvalidKeySpecException if supplied key specification was faulty.
	 * @throws IOException if communication problem occurred with underlying systems.
	 */
	

	protected EciesNistP256EncryptedKey eCEISEncryptSymmetricKey(PublicKeyAlgorithm publicKeyAlgorithm, PublicKey encryptionKey, Key symmetricKey) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IllegalArgumentException, InvalidKeySpecException, IOException{
		if(publicKeyAlgorithm != PublicKeyAlgorithm.ecies_nistp256){
			throw new IllegalArgumentException("Unsupported encryption public key algorithm: " + publicKeyAlgorithm);
		}
		byte[] keyData = symmetricKey.getEncoded();
		
		IESCipher eCIESCipher = new ECIES();
		eCIESCipher.engineInit(Cipher.ENCRYPT_MODE, encryptionKey, new IESParameterSpec(null, null, 128),secureRandom);
				
		byte[] encryptedData = eCIESCipher.engineDoFinal(keyData, 0, keyData.length);
		byte[] v = new byte[ECIES_NIST_P256_V_LENGTH];
		System.arraycopy(encryptedData, 0, v, 0,ECIES_NIST_P256_V_LENGTH);
        
        EccPoint p = new EccPoint(publicKeyAlgorithm);
        p.deserialize(new DataInputStream(new ByteArrayInputStream(v)));
        
		byte[] c = new byte[publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength()];
		byte[] t = new byte[EciesNistP256EncryptedKey.OUTPUT_TAG_LENGTH];
		System.arraycopy(encryptedData, ECIES_NIST_P256_V_LENGTH, c, 0, publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength());
		System.arraycopy(encryptedData, ECIES_NIST_P256_V_LENGTH + publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength(), t, 0, EciesNistP256EncryptedKey.OUTPUT_TAG_LENGTH);
		return new EciesNistP256EncryptedKey(publicKeyAlgorithm, p, c,t); 
	}
	
	/**
	 * Help method to perform a ECIES decryption of a symmetric key. 
	 * 
	 * @param eciesNistP256EncryptedKey the EciesNistP256EncryptedKey header value from the SecuredMessage
	 * @param decryptionKey the receiptients private key
	 * @return a decrypted symmetric key.
	 * 
	 * @throws InvalidKeyException if supplied key was corrupt.
	 * @throws InvalidAlgorithmParameterException if algorithm was badly specified.
	 * @throws IllegalBlockSizeException if encrypted data was corrupt.
	 * @throws BadPaddingException if encrypted data was corrupt.
	 * @throws IllegalArgumentException if arguments where invalid or algorithm not supported.
	 * @throws InvalidKeySpecException if supplied key specification was faulty.
	 * @throws IOException if communication problem occurred with underlying systems.
	 */
	 
	protected Key eCEISDecryptSymmetricKey(EciesNistP256EncryptedKey eciesNistP256EncryptedKey, PrivateKey decryptionKey) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IllegalArgumentException, InvalidKeySpecException, IOException{
		if(eciesNistP256EncryptedKey.getPublicKeyAlgorithm() != PublicKeyAlgorithm.ecies_nistp256){
			throw new IllegalArgumentException("Unsupported encryption public key algorithm: " + eciesNistP256EncryptedKey.getPublicKeyAlgorithm() );
		}
		
		IESCipher eCIESCipher = new ECIES();
		eCIESCipher.engineInit(Cipher.DECRYPT_MODE, decryptionKey, new IESParameterSpec(null, null, 128),secureRandom);
				
		byte[] encryptedData = new byte[ECIES_NIST_P256_V_LENGTH + eciesNistP256EncryptedKey.getPublicKeyAlgorithm().getRelatedSymmetricAlgorithm().getKeyLength() + EciesNistP256EncryptedKey.OUTPUT_TAG_LENGTH];
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dis = new DataOutputStream(baos);
		
		eciesNistP256EncryptedKey.getV().serialize(dis);
		baos.close();
		System.arraycopy(baos.toByteArray(), 0, encryptedData, 0, ECIES_NIST_P256_V_LENGTH);
		System.arraycopy(eciesNistP256EncryptedKey.getC(), 0, encryptedData, ECIES_NIST_P256_V_LENGTH, eciesNistP256EncryptedKey.getPublicKeyAlgorithm().getRelatedSymmetricAlgorithm().getKeyLength());
		System.arraycopy(eciesNistP256EncryptedKey.getT(), 0, encryptedData, ECIES_NIST_P256_V_LENGTH+eciesNistP256EncryptedKey.getPublicKeyAlgorithm().getRelatedSymmetricAlgorithm().getKeyLength(), EciesNistP256EncryptedKey.OUTPUT_TAG_LENGTH);
		
		byte[] decryptedData = eCIESCipher.engineDoFinal(encryptedData, 0, encryptedData.length);

		return new SecretKeySpec(decryptedData, "AES");
	}
	
	
	/**
	 * Help method to perform a symmetric encrypt of data.
	 * 
	 * @param symmetricAlgorithm the algorithm used to encrypt the data.
	 * @param data the encrypted data.
	 * @param symmetricKey the encrypt key.
	 * @param nounce related nounce.
	 * @return the encrypt clear text data.
	 * 
	 * @throws IllegalArgumentException if arguments where invalid or algorithm not supported.
	 * @throws NoSuchAlgorithmException if algorithm isn't available in underlying provider.
	 * @throws IllegalBlockSizeException if encrypted data was corrupt.
	 * @throws BadPaddingException if encrypted data was corrupt.
	 * @throws InvalidKeyException if supplied key was corrupt.
	 * @throws InvalidAlgorithmParameterException if algorithm was badly specified.
	 * @throws NoSuchProviderException if underlying provider was't installed properly.
	 * @throws NoSuchPaddingException if encrypted data was corrupt.
	 */
	protected byte[] symmetricEncrypt(SymmetricAlgorithm symmetricAlgorithm, byte[] data, Key symmetricKey, byte[] nounce) throws IllegalArgumentException, 
	                                   																						   NoSuchAlgorithmException, 
	                                   																						   IllegalBlockSizeException, 
	                                   																						   BadPaddingException, 
	                                   																						   InvalidKeyException, 
	                                   																						   InvalidAlgorithmParameterException, 
	                                   																						   NoSuchProviderException, 
	                                   																						   NoSuchPaddingException{

		Cipher c = getSymmetricCipher(symmetricAlgorithm, true);
	    c.init(Cipher.ENCRYPT_MODE, symmetricKey, new IvParameterSpec(nounce));
	    
		return c.doFinal(data);	
	}
	
	/**
	 * Help method to perform a symmetric decrypt of data.
	 * 
	 * @param symmetricAlgorithm the algorithm used to encrypt the data.
	 * @param data the encrypted data.
	 * @param symmetricKey the decryption key.
	 * @param nounce related nounce.
	 * @return the decrypted clear text data.
	 * 
	 * @throws IllegalArgumentException if arguments where invalid or algorithm not supported.
	 * @throws NoSuchAlgorithmException if algorithm isn't available in underlying provider.
	 * @throws IllegalBlockSizeException if encrypted data was corrupt.
	 * @throws BadPaddingException if encrypted data was corrupt.
	 * @throws InvalidKeyException if supplied key was corrupt.
	 * @throws InvalidAlgorithmParameterException if algorithm was badly specified.
	 * @throws NoSuchProviderException if underlying provider was't installed properly.
	 * @throws NoSuchPaddingException if encrypted data was corrupt.
	 */
	protected byte[] symmetricDecrypt(SymmetricAlgorithm symmetricAlgorithm, byte[] data, Key symmetricKey, byte[] nounce) throws IllegalArgumentException, 
	                                   																						   NoSuchAlgorithmException, 
	                                   																						   IllegalBlockSizeException, 
	                                   																						   BadPaddingException, 
	                                   																						   InvalidKeyException, 
	                                   																						   InvalidAlgorithmParameterException, 
	                                   																						   NoSuchProviderException, 
	                                   																						   NoSuchPaddingException{
		
		Cipher c = getSymmetricCipher(symmetricAlgorithm, false);
	    c.init(Cipher.DECRYPT_MODE, symmetricKey, new IvParameterSpec(nounce));
	    
		return c.doFinal(data);	
	}
	
	private Map<String, Cipher> chiphers = new HashMap<String, Cipher>();
	
	protected Cipher getSymmetricCipher(SymmetricAlgorithm symmetricAlgorithm, boolean encrypt) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{
		Cipher retval = null;
		if(symmetricAlgorithm != SymmetricAlgorithm.aes_128_ccm){
	    	throw new IllegalArgumentException("Unsupported symmetric chipher: " + symmetricAlgorithm);
	    }
	    if(encrypt){
	      retval = chiphers.get(symmetricAlgorithm + "_encrypt");
	      if(retval == null){
	    	  retval = Cipher.getInstance("AES/CCM/NoPadding", "BC");
	    	  chiphers.put(symmetricAlgorithm + "_encrypt", retval); 
	      }
	    }else{
		      retval = chiphers.get(symmetricAlgorithm + "_decrypt");
		      if(retval == null){
		    	  retval = Cipher.getInstance("AES/CCM/NoPadding", "BC");
		    	  chiphers.put(symmetricAlgorithm + "_encrypt", retval); 
		      }	
	    }
	    
	    return retval;
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#disconnect()
	 */
	@Override
	public void disconnect() throws IOException {
		
		
	}
	
	/**
	 * Method that adds a header field in a sorted order depending on header field type value.
	 * 
	 * @param secureMessage secure message to add header value to in sort order.
	 * @param headerField header to add.
	 */
	protected void addHeader(SecuredMessage secureMessage, HeaderField headerField) {
		List<HeaderField> headerFields = secureMessage.getHeaderFields();
		for(int i = 0; i < headerFields.size();i++){
			if(headerFields.get(i).getHeaderFieldType().getByteValue() > headerField.getHeaderFieldType().getByteValue()){
				headerFields.add(i, headerField);
				return;
			}
		}
		
		headerFields.add(headerField);
	}
	
	/**
	 * Help method to find a specific header field in a secure message.
	 * 
	 * @param secureMessage the secure message to lookup header fields.
	 * @param type the type of header to find
	 * @param required if exception should be thrown if header could be found.
	 * @return header field of specified type, or null if no header field could be found and it's not required.
	 * @throws IllegalArgumentException if no required header field of specified type could be found.
	 */
	protected HeaderField findHeader(SecuredMessage secureMessage, HeaderFieldType type, boolean required) throws IllegalArgumentException{
		HeaderField retval = null;
		for( HeaderField hf : secureMessage.getHeaderFields()){
			if(hf.getHeaderFieldType() == type){
				retval = hf;
				break;
			}
		}
		
		if(required && retval == null){
			throw new IllegalArgumentException("Couldn't find header of type " + type + " in secure message.");
		}
		
		return retval;
	}
	
	/**
	 * Help method to find RecipientInfo for a given certificate.
	 * 
	 * @param receiverCertificate the certificate that matches the RecipientInfo to find.
	 * @param recipients list of recipients in message header list.
	 * @return the related RecipientInfo
	 * @throws IllegalArgumentException if no matching RecipientInfo could be found.
	 * @throws IOException if certificate encoding problems occurred. 
	 */
	private RecipientInfo findRecipientInfo(Certificate receiverCertificate,
			List<StructSerializer> recipients) throws IllegalArgumentException, IOException{
		HashedId8 hashId = new HashedId8(receiverCertificate.getEncoded());
		for(StructSerializer n : recipients){
			RecipientInfo ri = (RecipientInfo) n;
			if(ri.getCertId().equals(hashId)){
				return ri;
			}
		}
		throw new IllegalArgumentException("Error no recipient info found in header matching certificate with hashId: " + hashId.toString());
	}
	
	protected ECCurve.AbstractFp getECCurve(PublicKeyAlgorithm alg){
		if(alg == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256 || alg == PublicKeyAlgorithm.ecies_nistp256){
			return ecNistP256Curve;
		}
		throw new IllegalArgumentException("Unsupported EC Algorithm: " + alg);
	}
	
	protected ECPublicKey getECPublicKeyFromECPoint(PublicKeyAlgorithm alg, ECPoint eCPoint) throws InvalidKeySpecException{
		ECPublicKeySpec spec = new ECPublicKeySpec(eCPoint, getECParameterSpec(alg));
		return (ECPublicKey) keyFact.generatePublic(spec);
	}
	
	protected ECParameterSpec getECParameterSpec(PublicKeyAlgorithm alg){
		if(alg == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256 || alg == PublicKeyAlgorithm.ecies_nistp256){
			return ecNistP256Spec;
		}
		throw new IllegalArgumentException("Unsupported EC Algorithm: " + alg);
	}
	
	protected BCECPublicKey convertECPublicKeyToBCECPublicKey(PublicKeyAlgorithm alg, java.security.interfaces.ECPublicKey ecPublicKey) throws InvalidKeySpecException{
		if(ecPublicKey instanceof BCECPublicKey){
			return (BCECPublicKey) ecPublicKey;
		}
		
		org.bouncycastle.math.ec.ECPoint ecPoint = EC5Util.convertPoint(getECCurve(alg), ecPublicKey.getW(), false);
		ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, getECParameterSpec(alg));
		
		return (BCECPublicKey) keyFact.generatePublic(keySpec);

	}
	
	protected EccPoint getVerificationKey(Certificate signerCert) throws IllegalArgumentException {
		for(SubjectAttribute attr : signerCert.getSubjectAttributes()){
			if(attr.getSubjectAttributeType() == SubjectAttributeType.verification_key){
				return attr.getPublicKey().getPublicKey();
			}
		}
		throw new IllegalArgumentException("Couldn't retrieve verification key from signer certificate.");
	}
	
	protected org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey getEncryptionKey(Certificate cert) throws IllegalArgumentException {
		for(SubjectAttribute attr : cert.getSubjectAttributes()){
			if(attr.getSubjectAttributeType() == SubjectAttributeType.encryption_key){
				return attr.getPublicKey();
			}
		}
		throw new IllegalArgumentException("Couldn't retrieve encryption key from certificate.");
	}

	
	protected byte[] serializeCertWithoutSignature(Certificate certificate) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		dos.write(certificate.getVersion());		
		SerializationHelper.encodeVariableSizeVector(dos, certificate.getSignerInfos());
		certificate.getSubjectInfo().serialize(dos);
		SerializationHelper.encodeVariableSizeVector(dos, certificate.getSubjectAttributes());
		SerializationHelper.encodeVariableSizeVector(dos, certificate.getValidityRestrictions());
		return baos.toByteArray();
	}
	
	
	protected byte[] serializeDataToBeSignedInSecuredMessage(SecuredMessage message, Signature signature) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		dos.write(message.getProtocolVersion());
		dos.write(message.getSecurityProfile());
		
		SerializationHelper.encodeVariableSizeVector(dos, message.getHeaderFields());
		
		serializeTotalPayloadSize(dos, message.getPayloadFields());
		for(Payload pl : message.getPayloadFields()){
			if(pl.getPayloadType() == PayloadType.encrypted || pl.getPayloadType() == PayloadType.unsecured){
				// if payload shouldn't be included in the signature should only the type and length be included
			    dos.write(pl.getPayloadType().getByteValue());
			    IntX size = new IntX(pl.getData().length);
			    size.serialize(dos);
			}else{
				pl.serialize(dos);
			}
		}
				
		// Serialize all trailer fields until a signature is found
		serializeTotalSignedTrailerLength(dos, message.getTrailerFields(), signature);
		for(TrailerField tf : message.getTrailerFields()){
		   if(tf.getTrailerFieldType() != TrailerFieldType.signature){
                tf.serialize(dos);
		   }else{
			   // Don't calculate any more fields in the signature.
			   break;
		   }
		}
		
		byte[] retval = baos.toByteArray();
		return retval;
	}

	protected SignerInfo findFirstValidSignerInfo(Certificate certificate) {
		for(SignerInfo si : certificate.getSignerInfos()){
			SignerInfoType type = si.getSignerInfoType();
			if(type == SignerInfoType.self || type == SignerInfoType.certificate || type == SignerInfoType.certificate_chain){
				return si;
			}
		}
		throw new IllegalArgumentException("No signer info of type self, certificate or certificate_chain found when verifying certificate");
	}
	
	protected Certificate findFirstValidCertificateInMessage(SecuredMessage msg) {
		for(HeaderField hf : msg.getHeaderFields()){
			if(hf.getHeaderFieldType() == HeaderFieldType.signer_info){
				SignerInfo si = hf.getSigner();			
				if(si.getSignerInfoType() == SignerInfoType.certificate){
					return si.getCertificate();
				}
			}
		}
		throw new IllegalArgumentException("No signer info of type certificate or certificate_chain found when verifying secured message");
	}
	

	protected Signature findSignatureInMessage(SecuredMessage message) throws IllegalArgumentException {
		if(message.getTrailerFields() != null){
		for(TrailerField tf : message.getTrailerFields()){
			if(tf.getTrailerFieldType() == TrailerFieldType.signature){
				return tf.getSignature();
			}
		}
		}
		throw new IllegalArgumentException("No signature trailer field found in secured message.");
	}


	protected void serializeTotalPayloadSize(DataOutputStream out, List<? extends StructSerializer> variableSizeVector) throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);    		 
		for(StructSerializer next: variableSizeVector){
			next.serialize(dos);
		}
		byte[] data = baos.toByteArray();
		IntX size = new IntX(data.length);
		size.serialize(out);
	}
	

	protected void serializeTotalSignedTrailerLength(DataOutputStream out, List<TrailerField> variableSizeVector, Signature signature) throws IOException, IllegalArgumentException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);  		
		for(TrailerField next: variableSizeVector){
			if(next.getTrailerFieldType() == TrailerFieldType.signature){
				break;
			}
			next.serialize(dos);
		}
		byte[] data = baos.toByteArray();
		int length = data.length;
		length += calculateSignatureLength(signature);
		IntX size = new IntX(length);
		size.serialize(out);
	}

	protected int calculateSignatureLength(Signature signature) throws IllegalArgumentException {
		if(signature.getPublicKeyAlgorithm() == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256){			
			if(signature.getSignatureValue().getR().getEccPointType() == EccPointType.uncompressed){
				return 2 + (3* signature.getPublicKeyAlgorithm().getFieldSize()); // public key alg type (1 byte) + EccPointType (1 byte) + R (2 * (x+y) field size in bytes) + s (field size in bytes)
			}
			return 2 + (2* signature.getPublicKeyAlgorithm().getFieldSize()); // public key alg type (1 byte) + EccPointType (1 byte) + R (field size in bytes) + s (field size in bytes)
		}
		throw new IllegalArgumentException("Error unsupported digital signature algorithm " + signature.getPublicKeyAlgorithm());
	}
	
	
}
