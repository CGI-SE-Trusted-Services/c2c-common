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
package org.certificateservices.custom.c2x.common.crypto;

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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.EphemeralKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyEncoder;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIES;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.IESKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.common.EncodeHelper;
import org.certificateservices.custom.c2x.common.crypto.Algorithm.Hash;
import org.certificateservices.custom.c2x.common.crypto.Algorithm.Symmetric;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EcdsaP256Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EciesP256EncryptedKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.UncompressedEccPoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices;
import org.certificateservices.custom.c2x.its.crypto.ITSCryptoManager;
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
public class DefaultCryptoManager implements ITSCryptoManager, Ieee1609Dot2CryptoManager {
	
   
	protected ECParameterSpec ecNistP256Spec = ECNamedCurveTable.getParameterSpec("P-256");
	protected ECParameterSpec brainpoolp256r1Spec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
	protected ECParameterSpec brainpoolp384r1Spec = ECNamedCurveTable.getParameterSpec("brainpoolp384r1");
	
	protected KeyPairGenerator ecNistP256Generator;
	protected KeyPairGenerator brainpoolp256r1Generator;
	protected KeyPairGenerator brainpoolp384r1Generator;
	protected KeyGenerator aES128Generator;
	protected SecureRandom secureRandom = new SecureRandom();
	protected SecP256R1Curve ecNistP256Curve = new SecP256R1Curve();
	protected ECCurve brainpoolp256r1 = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1).getCurve();
	protected KeyFactory keyFact;
	protected MessageDigest sha256Digest;
	protected MessageDigest sha384Digest;
	protected ECQVHelper ecqvHelper;
	
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
	public void setupAndConnect(CryptoManagerParams params) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, IOException, BadCredentialsException, SignatureException{
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
			brainpoolp256r1Generator = KeyPairGenerator.getInstance("ECDSA", provider);
			brainpoolp256r1Generator.initialize(brainpoolp256r1Spec,secureRandom);
			brainpoolp384r1Generator = KeyPairGenerator.getInstance("ECDSA", provider);
			brainpoolp384r1Generator.initialize(brainpoolp384r1Spec,secureRandom);
			sha256Digest = MessageDigest.getInstance("SHA-256","BC");
			sha384Digest = MessageDigest.getInstance("SHA-384","BC");
			keyFact = KeyFactory.getInstance("ECDSA", "BC");
			aES128Generator = KeyGenerator.getInstance("AES","BC");
			aES128Generator.init(128);
			
			ecqvHelper = new ECQVHelper(this); 
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
		
		Key symmetricKey = generateSecretKey(encryptionAlg);
		List<Encodable> reciptientInfos = new ArrayList<Encodable>();
		// Verify that all certificates have encryption keys
		for(Certificate c : receipients){
			org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey encKey = getEncryptionKey(c);
			PublicKey encryptionKey = (PublicKey) decodeEccPoint(encKey.getPublicKeyAlgorithm(), encKey.getPublicKey());
			HashedId8 certHash = new HashedId8(c.getEncoded());
			EciesNistP256EncryptedKey encryptedKey;
			if(secureMessage.getProtocolVersion() == SecuredMessage.PROTOCOL_VERSION_1){
				encryptedKey = itsEceisEncryptSymmetricKeyVer1(encryptionAlg, encryptionKey, symmetricKey);
			}else{
				encryptedKey = itsEceisEncryptSymmetricKeyVer2(encryptionAlg, encryptionKey, symmetricKey);
			}
			reciptientInfos.add(new RecipientInfo(certHash, encryptedKey));
		}
		
		addHeader(secureMessage, new HeaderField(secureMessage.getProtocolVersion(),HeaderFieldType.recipient_info, reciptientInfos));
		addHeader(secureMessage,new HeaderField(secureMessage.getProtocolVersion(),encParams));
		
		for(Payload payload : secureMessage.getPayloadFields()){
			if(payload.getPayloadType() == payloadType){
			   payload.setData(symmetricEncrypt(encryptionAlg.getRelatedSymmetricAlgorithm(), payload.getData(), symmetricKey, nounce));
			}
		}

		return secureMessage;
	}
	

	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#signAndEncryptSecureMessage(SecuredMessage, Certificate, Certificate[],SignerInfoType, PublicKeyAlgorithm, PrivateKey, PublicKeyAlgorithm, List)
	 */
	@Override
	public SecuredMessage encryptAndSignSecureMessage(
			SecuredMessage secureMessage, Certificate signerCertificate, Certificate[] signerCACertificates,
			SignerInfoType signInfoType, PublicKeyAlgorithm signAlg,
			PrivateKey signPrivateKey, PublicKeyAlgorithm encryptionAlg,
			List<Certificate> receipients) throws IllegalArgumentException,
			GeneralSecurityException, IOException {
		SecuredMessage encryptedMessage = encryptSecureMessage(secureMessage, encryptionAlg, receipients, PayloadType.signed_and_encrypted);
		return signSecureMessage(encryptedMessage, signerCertificate, signerCACertificates, signInfoType, signAlg, signPrivateKey);
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
	  Key symmetricKey;
	  if(secureMessage.getProtocolVersion() == SecuredMessage.PROTOCOL_VERSION_1){
		  symmetricKey = itsEceisDecryptSymmetricKeyVer1(receipentInfo.getPkEncryption(), receiverKey);
	  }else{
		  symmetricKey = itsEciesDecryptSymmetricKeyVer2(receipentInfo.getPkEncryption(), receiverKey);
	  }
	
	  for(Payload payload : secureMessage.getPayloadFields()){
			if(payload.getPayloadType() == payloadType){
			   payload.setData(symmetricDecrypt(receipentInfo.getPublicKeyAlgorithm().getRelatedSymmetricAlgorithm(), payload.getData(), symmetricKey, encParams.getNounce()));
			}
		}

	  return secureMessage;
	}	
	
	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#genNounce(AlgorithmIndicator)
	 */
	@Override
	public byte[] genNounce(AlgorithmIndicator alg) throws IllegalArgumentException, GeneralSecurityException{
		if( alg.getAlgorithm().getSymmetric() == null){
			throw new IllegalArgumentException("Error algorithm scheme doesn't support symmetric encryption");
		}
		int nounceLen = alg.getAlgorithm().getSymmetric().getNounceLength();
		byte[] nounce = new byte[nounceLen];
		secureRandom.nextBytes(nounce);
		
		return nounce;
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#constructSecretKey(AlgorithmIndicator, byte[])
	 */
	@Override
	public SecretKey constructSecretKey(AlgorithmIndicator alg, byte[] keyData) throws IllegalArgumentException, GeneralSecurityException{
		if(alg.getAlgorithm().getSymmetric() != Symmetric.aes128Ccm){
			throw new IllegalArgumentException("Count construct secret key from unsupported algorithm: " + alg);
		}
		return new SecretKeySpec(keyData, "AES");
	}

	/**
	 * @see org.certificateservices.custom.c2x.common.its.CryptoManager#signSecureMessag
	 */
	@Override
	public SecuredMessage signSecureMessage(SecuredMessage secureMessage, Certificate signerCertificate, Certificate[] signerCACertificates,SignerInfoType signerInfoType, PublicKeyAlgorithm alg,
			PrivateKey privateKey) throws IllegalArgumentException, SignatureException, IOException {	
		if(secureMessage.getProtocolVersion() == SecuredMessage.PROTOCOL_VERSION_1 &&
		   signerInfoType == SignerInfoType.certificate_chain){
			throw new IllegalArgumentException("Error signing SecureMessage, Version 1 message doesn't support signer info certificate_chain");
		}
		
        if(signerInfoType == SignerInfoType.certificate){
            addHeader(secureMessage,new HeaderField(secureMessage.getProtocolVersion(),new SignerInfo(signerCertificate)));
        }else{ 
        	if(signerInfoType == SignerInfoType.certificate_chain){
        		List<Certificate> chain = new ArrayList<Certificate>();
        		if(signerCACertificates != null){
        			for(Certificate cACert :signerCACertificates){
        				chain.add(cACert);
        			}
        			chain.add(signerCertificate);
        		}
        		addHeader(secureMessage,new HeaderField(secureMessage.getProtocolVersion(),new SignerInfo(chain)));
        	}else{
        		try {
        			HashedId8 hash = new HashedId8(signerCertificate, this);
        			addHeader(secureMessage,new HeaderField(secureMessage.getProtocolVersion(),new SignerInfo(hash)));
        		} catch (NoSuchAlgorithmException e) {
        			throw new SignatureException("Error generating secured message, no such algorithm: " + e.getMessage(),e);
        		} catch (InvalidKeySpecException e) {
        			throw new SignatureException("Error generating secured message, invalid key: " + e.getMessage(),e);
				}		
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
		
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new IllegalArgumentException("Error no signature algorithm specified");
		}
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

			ByteArrayOutputStream baos = new ByteArrayOutputStream(sigAlg.getFieldSize());
			EncodeHelper.writeFixedFieldSizeKey(sigAlg.getFieldSize(), baos, s);	    

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
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#signMessageDigest(byte[], AlgorithmIndicator, PrivateKey)
	 */
	@Override
	public org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signMessageDigest(
			byte[] digest, AlgorithmIndicator alg, PrivateKey privateKey)
			throws IllegalArgumentException, SignatureException, IOException {
		
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new IllegalArgumentException("Error no signature algorithm specified");
		}
		ASN1InputStream asn1InputStream = null;
		try{
		
			java.security.Signature signature = java.security.Signature.getInstance("NONEwithECDSA", provider); 
			signature.initSign(privateKey);
			signature.update(digest);
			byte[] dERSignature = signature.sign();


			ByteArrayInputStream inStream = new ByteArrayInputStream(dERSignature);
			asn1InputStream = new ASN1InputStream(inStream);

			DLSequence dLSequence = (DLSequence) asn1InputStream.readObject();
			BigInteger r = ((ASN1Integer) dLSequence.getObjectAt(0)).getPositiveValue();
			BigInteger s = ((ASN1Integer) dLSequence.getObjectAt(1)).getPositiveValue();

			ByteArrayOutputStream baos = new ByteArrayOutputStream(sigAlg.getFieldSize());
			EncodeHelper.writeFixedFieldSizeKey(sigAlg.getFieldSize(), baos, s);	    

			return new org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature(
					getSignatureChoice(sigAlg),new EcdsaP256Signature(new EccP256CurvePoint(r), 
					baos.toByteArray()));

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
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#signMessage(byte[], AlgorithmIndicator, PrivateKey, CertificateType, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate)
	 */
	@Override
	public org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signMessage(
			byte[] message, AlgorithmIndicator alg, PublicKey pubKey, PrivateKey privateKey,
			CertificateType certType,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signCert)
			throws IllegalArgumentException, SignatureException, IOException {
		
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new IllegalArgumentException("Error no signature algorithm specified");
		}
		
		try{
			  return signMessageDigest(genIEEECertificateDigest(alg, message, signCert), alg, privateKey);
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
		
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new IllegalArgumentException("Error no signature algorithm specified");
		}
		
		if(alg ==PublicKeyAlgorithm.ecdsa_nistp256_with_sha256){
			try{
				EcdsaSignature ecdsaSignature = signature.getSignatureValue();

				// Create Signature Data
				ASN1Integer asn1R = new ASN1Integer(ecdsaSignature.getR().getX());		    
				ASN1Integer asn1S = new ASN1Integer(EncodeHelper.readFixedFieldSizeKey(sigAlg.getFieldSize(), new ByteArrayInputStream(ecdsaSignature.getSignatureValue())));
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
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#verifySignatureDigest(byte[], org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature, PublicKey)
	 */
	@Override
	public boolean verifySignatureDigest(
			byte[] digest,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signature,
			PublicKey publicKey) throws IllegalArgumentException,
			SignatureException, IOException {
		 
		AlgorithmIndicator alg = getSignatureAlgorithm(signature.getType());
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new IllegalArgumentException("Error no signature algorithm specified");
		}
		
		try{
			EcdsaP256Signature ecdsaSignature = (EcdsaP256Signature) signature.getValue();

			// Create Signature Data
			EccP256CurvePoint xPoint = ecdsaSignature.getR();
			BigInteger r = new BigInteger(1,((COEROctetStream) xPoint.getValue()).getData());
			ASN1Integer asn1R = new ASN1Integer(r);		    
			ASN1Integer asn1S = new ASN1Integer(EncodeHelper.readFixedFieldSizeKey(sigAlg.getFieldSize(), new ByteArrayInputStream(ecdsaSignature.getS())));
			DLSequence dLSequence = new DLSequence(new ASN1Encodable[]{asn1R, asn1S});
			byte[] dERSignature = dLSequence.getEncoded();

			java.security.Signature sig = java.security.Signature.getInstance("NONEwithECDSA", provider); 
			sig.initVerify(publicKey);
			sig.update(digest);
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
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#verifySignature(byte[], org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate)
	 */
	@Override
	public boolean verifySignature(
			byte[] message,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signature,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signerCert)
			throws IllegalArgumentException, SignatureException, IOException {
		if(signerCert.getType() == CertificateType.explicit){
			PublicVerificationKey pubVerKey = (PublicVerificationKey) signerCert.getToBeSigned().getVerifyKeyIndicator().getValue();
			return verifyExplicitCertSignature(message, signature, signerCert, (EccP256CurvePoint) pubVerKey.getValue());
		}else{
			throw new IllegalArgumentException("Implicit certificates not supported by this method");
		}
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#verifySignature(byte[], org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate, PublicKey)
	 */
	@Override
	public boolean verifySignature(
			byte[] message,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signature,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signerCert,
			PublicKey signedPublicKey)
			throws IllegalArgumentException, SignatureException, IOException {
		if(signerCert.getType() == CertificateType.explicit){
			PublicVerificationKey pubVerKey = (PublicVerificationKey) signerCert.getToBeSigned().getVerifyKeyIndicator().getValue();
			return verifyExplicitCertSignature(message, signature, signerCert, (EccP256CurvePoint) pubVerKey.getValue());
		}else{
			return verifyImplicitCertSignature(message, signature,signerCert,signedPublicKey);
		}
	}
	
	/**
	 *  {@link org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#verifyCertificate(org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate)}
	 */
	@Override
	public boolean verifyCertificate(
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signerCertificate)
			throws IllegalArgumentException, SignatureException, IOException {
		if(certificate.equals(signerCertificate)){
			return verifySignature(certificate.getToBeSigned().getEncoded(), certificate.getSignature(), (PublicVerificationKey) certificate.getToBeSigned().getVerifyKeyIndicator().getValue());
		}else{
			return verifySignature(certificate.getToBeSigned().getEncoded(), certificate.getSignature(), signerCertificate);
		}
		
	}
	

	protected boolean verifySignature(
			byte[] message,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signature,
			PublicVerificationKey publicVerificationKey)
			throws IllegalArgumentException, SignatureException, IOException {
		
			return verifyExplicitCertSignature(message, signature, null, (EccP256CurvePoint) publicVerificationKey.getValue());
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
			throws IllegalArgumentException, InvalidSignatureException, SignatureException, IOException {
		Certificate signerCert = findFirstValidCertificateInMessage(message);
		verifySecuredMessage(message, signerCert);
	}

	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifySecuredMessage(SecuredMessage, Certificate)
	 */
	@Override
	public void verifySecuredMessage(SecuredMessage message,
			Certificate signerCert) throws IllegalArgumentException, InvalidSignatureException,
			SignatureException, IOException {
		Signature signature = findSignatureInMessage(message);
		byte[] msgData = serializeDataToBeSignedInSecuredMessage(message, signature);
	
		if(!verifySignature(msgData, signature, signerCert)){
			throw new InvalidSignatureException("Error verifying signature of SecuredMessage");
		}
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifyAndDecryptSecuredMessage(SecuredMessage, Certificate, PrivateKey)
	 */
	@Override
	public SecuredMessage verifyAndDecryptSecuredMessage(
			SecuredMessage message, Certificate receiverCertificate,
			PrivateKey receiverKey) throws IllegalArgumentException, InvalidSignatureException, GeneralSecurityException, IOException{
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
			throws IllegalArgumentException, InvalidSignatureException, GeneralSecurityException, IOException{
		verifySecuredMessage(message, signerCert);
		return decryptSecureMessage(message, receiverCertificate, receiverKey, PayloadType.signed_and_encrypted);
	}

	/**
	 * Supports ECDSA P256 ad BrainPool P256r1
	 * 
	 * @see org.certificateservices.custom.c2x.common.crypto.CryptoManager#generateKeyPair(AlgorithmIndicator)
	 */
	public KeyPair generateKeyPair(AlgorithmIndicator alg){
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new IllegalArgumentException("Error invalid algorithm when generating key pair: "+ alg);
		}
		if(sigAlg == Algorithm.Signature.ecdsaNistP256){
			return ecNistP256Generator.generateKeyPair();
		}
		if(sigAlg == Algorithm.Signature.ecdsaBrainpoolP256r1){
			return brainpoolp256r1Generator.generateKeyPair();
		}
		if(sigAlg == Algorithm.Signature.ecdsaBrainpoolP384r1){
			return brainpoolp384r1Generator.generateKeyPair();
		}
		throw new IllegalArgumentException("Error unsupported algorithm when generating key pair: " + sigAlg);
	}
	
	/**
	 * Supports acm aes 128
	 * 
	 * @see org.certificateservices.custom.c2x.common.crypto.CryptoManager#generateSecretKey(AlgorithmIndicator)
	 */
	@Override
	public SecretKey generateSecretKey(AlgorithmIndicator alg){
		Algorithm.Symmetric symAlg = alg.getAlgorithm().getSymmetric();
		if(symAlg == null){
			throw new IllegalArgumentException("Error invalid algorithm when generating secret key: "+ alg);
		}
		if(symAlg == Algorithm.Symmetric.aes128Ccm){
			return aES128Generator.generateKey();
		}
		throw new IllegalArgumentException("Error unsupported algorithm when generating secret key: " + symAlg);
	}
		
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#encodeEccPoint(PublicKeyAlgorithm, EccPointType, PublicKey)
	 */
	public EccPoint encodeEccPoint(PublicKeyAlgorithm alg, EccPointType type, PublicKey publicKey) throws IllegalArgumentException, InvalidKeySpecException{
		if(! (publicKey instanceof java.security.interfaces.ECPublicKey)){
			throw new IllegalArgumentException("Only ec public keys are supported, not " + publicKey.getClass().getSimpleName());
		}
		BCECPublicKey bcPub = toBCECPublicKey(alg, (java.security.interfaces.ECPublicKey) publicKey);
		
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
	 * @see org.certificateservices.custom.c2x.its.crypto.ITSCryptoManager#decodeEccPoint(PublicKeyAlgorithm, EccPoint)
	 */
	public Object decodeEccPoint(AlgorithmIndicator alg, EccPoint point) throws InvalidKeySpecException{
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
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#encodeEccPoint(BasePublicEncryptionKeyChoices, EccP256CurvePointChoices, PublicKey)
	 */
	@Override
	public EccP256CurvePoint encodeEccPoint(AlgorithmIndicator alg,
			EccP256CurvePointChoices type, PublicKey publicKey)
			throws IllegalArgumentException, InvalidKeySpecException {
		if(! (publicKey instanceof java.security.interfaces.ECPublicKey)){
			throw new IllegalArgumentException("Only ec public keys are supported, not " + publicKey.getClass().getSimpleName());
		}
		BCECPublicKey bcPub = toBCECPublicKey(alg, (java.security.interfaces.ECPublicKey) publicKey);

		if(type == EccP256CurvePointChoices.uncompressed){
			return new EccP256CurvePoint(bcPub.getW().getAffineX(), bcPub.getW().getAffineY());
		}
		if(type == EccP256CurvePointChoices.compressedy0 || type == EccP256CurvePointChoices.compressedy1){
			return new EccP256CurvePoint(bcPub.getQ().getEncoded(true));            
		}
		if(type == EccP256CurvePointChoices.xonly){
			return new EccP256CurvePoint(bcPub.getW().getAffineX());
		}

		throw new IllegalArgumentException("Unsupported ecc point type: " + type);
	}

	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#decodeEccPoint(BasePublicEncryptionKeyChoices, EccP256CurvePoint)
	 */
	@Override
	public Object decodeEccPoint(AlgorithmIndicator alg,
			EccP256CurvePoint eccPoint) throws InvalidKeySpecException {
		switch(eccPoint.getType()){
		case fill:
			throw new InvalidKeySpecException("Unsupported EccPoint type: fill");
		case xonly:
			byte[] data = ((COEROctetStream) eccPoint.getValue()).getData();
		    return new BigInteger(1,data);	
		case compressedy0:
		case compressedy1:
			byte[] compData = ((COEROctetStream) eccPoint.getValue()).getData();
			byte[] compressedEncoding = new byte[compData.length +1];
			System.arraycopy(compData, 0, compressedEncoding, 1, compData.length);
			if(eccPoint.getType() == EccP256CurvePointChoices.compressedy0){
				compressedEncoding[0] = 0x02;
			}else{
				compressedEncoding[0] = 0x03;
			}
			return getECPublicKeyFromECPoint(alg, getECCurve(alg).decodePoint(compressedEncoding));
		case uncompressed:
			UncompressedEccPoint uep = (UncompressedEccPoint) eccPoint.getValue();
			BigInteger x = new BigInteger(1, uep.getX());
			BigInteger y = new BigInteger(1, uep.getY());
			return getECPublicKeyFromECPoint(alg, getECCurve(alg).createPoint(x, y));
		}
		return null;
	}

	
	/**
	 * @see org.certificateservices.custom.c2x.common.crypto.CryptoManager#digest(byte[], PublicKeyAlgorithm)
	 */
	public byte[] digest(byte[] message, AlgorithmIndicator alg) throws IllegalArgumentException, NoSuchAlgorithmException {
		Hash hashAlg = alg.getAlgorithm().getHash();
		if(hashAlg != null && hashAlg == Hash.sha256){
			sha256Digest.reset();
            sha256Digest.update(message); 
			return sha256Digest.digest();
		}
		if(hashAlg != null && hashAlg == Hash.sha384){
			sha384Digest.reset();
			sha384Digest.update(message);
			return sha384Digest.digest();
		}
		throw new IllegalArgumentException("Unsupported hash algorithm: " + alg);
	}
		
	
	/**
	 * Help method to generate a certificate digest according to 1609.2 section 5.3.1 Signature algorithm.
	 * @param alg the algorithm to use.
	 * @param messageData the message data to digest
	 * @param signerCertificate the certificate used for signing, null if selfsigned data.
	 * @throws NoSuchAlgorithmException 
	 * @throws IllegalArgumentException 
	 * @throws IOException 
	 */
	@Override
	public byte[] genIEEECertificateDigest(AlgorithmIndicator alg,byte[] messageData, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signerCertificate) throws IllegalArgumentException, NoSuchAlgorithmException, IOException{
		byte[] dataDigest = digest(messageData, alg);
		byte[] signerDigest;

		if(signerCertificate == null){
			signerDigest = digest(new byte[0], alg);
		}else{
			signerDigest = digest(signerCertificate.getEncoded(), alg);
		}
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(dataDigest);
		baos.write(signerDigest);
		
		byte[] retval = digest(baos.toByteArray(),alg);
		return retval;
		
	}
	
	protected final int ECIES_NIST_P256_V_LENGTH_VER1 = 65;
	protected final int ECIES_NIST_P256_V_LENGTH_VER2 = 33;
	
	/**
	 * Help method to perform a ECIES encryption to a recipient of a symmetric key according to the protool version 1 standard. 
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
	protected EciesNistP256EncryptedKey itsEceisEncryptSymmetricKeyVer1(PublicKeyAlgorithm publicKeyAlgorithm, PublicKey encryptionKey, Key symmetricKey) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IllegalArgumentException, InvalidKeySpecException, IOException{
		if(publicKeyAlgorithm != PublicKeyAlgorithm.ecies_nistp256){
			throw new IllegalArgumentException("Unsupported encryption public key algorithm: " + publicKeyAlgorithm);
		}
		byte[] keyData = symmetricKey.getEncoded();
		
		IESCipher eCIESCipher = new ECIES();
		eCIESCipher.engineInit(Cipher.ENCRYPT_MODE, encryptionKey, new IESParameterSpec(null, null, 128),secureRandom);
				
		byte[] encryptedData = eCIESCipher.engineDoFinal(keyData, 0, keyData.length);
		
		byte[] v = new byte[ECIES_NIST_P256_V_LENGTH_VER1];
		System.arraycopy(encryptedData, 0, v, 0,ECIES_NIST_P256_V_LENGTH_VER1);
        
        EccPoint p = new EccPoint(publicKeyAlgorithm);
        p.decode(new DataInputStream(new ByteArrayInputStream(v)));
        
		byte[] c = new byte[publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength()];
		byte[] t = new byte[EciesNistP256EncryptedKey.VER1_OUTPUT_TAG_LENGTH];
		System.arraycopy(encryptedData, ECIES_NIST_P256_V_LENGTH_VER1, c, 0, publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength());
		System.arraycopy(encryptedData, ECIES_NIST_P256_V_LENGTH_VER1 + publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength(), t, 0, EciesNistP256EncryptedKey.VER1_OUTPUT_TAG_LENGTH);
		
		return new EciesNistP256EncryptedKey(1,publicKeyAlgorithm, p, c,t); 
	}

	protected EciesNistP256EncryptedKey itsEceisEncryptSymmetricKeyVer2(PublicKeyAlgorithm publicKeyAlgorithm, PublicKey encryptionKey, Key symmetricKey) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IllegalArgumentException, InvalidKeySpecException, IOException{
		return itsEceisEncryptSymmetricKeyVer2(publicKeyAlgorithm,encryptionKey,symmetricKey,null,null,null);
	}

	/**
	 * Help method to perform a ECIES encryption to a recipient of a symmetric key according to the protocol version 2 standard. 
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
	protected EciesNistP256EncryptedKey itsEceisEncryptSymmetricKeyVer2(PublicKeyAlgorithm publicKeyAlgorithm, PublicKey encryptionKey, Key symmetricKey, byte[] derivation, byte[] encoding, byte[] nounce) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IllegalArgumentException, InvalidKeySpecException, IOException{
		if(publicKeyAlgorithm != PublicKeyAlgorithm.ecies_nistp256){
			throw new IllegalArgumentException("Unsupported encryption public key algorithm: " + publicKeyAlgorithm);
		}
		byte[] keyData = symmetricKey.getEncoded();


		IESCipher eCIESCipher = new IEEE1609Dot2ECIES();
		eCIESCipher.engineInit(Cipher.ENCRYPT_MODE, encryptionKey,  new IESParameterSpec(derivation, encoding, 128,-1, nounce, true),secureRandom);
				
		byte[] encryptedData = eCIESCipher.engineDoFinal(keyData, 0, keyData.length);
		
		byte[] v = new byte[ECIES_NIST_P256_V_LENGTH_VER2];
		System.arraycopy(encryptedData, 0, v, 0,ECIES_NIST_P256_V_LENGTH_VER2);
        
        EccPoint p = new EccPoint(publicKeyAlgorithm);
        p.decode(new DataInputStream(new ByteArrayInputStream(v)));
        
		byte[] c = new byte[publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength()];
		byte[] t = new byte[EciesNistP256EncryptedKey.VER2_OUTPUT_TAG_LENGTH];
		System.arraycopy(encryptedData, ECIES_NIST_P256_V_LENGTH_VER2, c, 0, publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength());
		System.arraycopy(encryptedData, ECIES_NIST_P256_V_LENGTH_VER2 + publicKeyAlgorithm.getRelatedSymmetricAlgorithm().getKeyLength(), t, 0, EciesNistP256EncryptedKey.VER2_OUTPUT_TAG_LENGTH);
		
		return new EciesNistP256EncryptedKey(SecuredMessage.PROTOCOL_VERSION_2,publicKeyAlgorithm, p, c,t); 
	}
	
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
	@Override
	public EncryptedDataEncryptionKey ieeeEceisEncryptSymmetricKey(EncryptedDataEncryptionKeyChoices keyType, PublicKey encryptionKey, SecretKey symmetricKey, AlgorithmIndicator alg,byte[] eciesDeviation) throws IllegalArgumentException, GeneralSecurityException, IOException{
		byte[] keyData = symmetricKey.getEncoded();

		IESCipher eCIESCipher = new IEEE1609Dot2ECIES();
		eCIESCipher.engineInit(Cipher.ENCRYPT_MODE, encryptionKey, new IESParameterSpec(eciesDeviation, null, 128,-1, null, true),secureRandom);
				
		byte[] encryptedData = eCIESCipher.engineDoFinal(keyData, 0, keyData.length);
		byte[] v = new byte[keyType.getVLength()];
		System.arraycopy(encryptedData, 0, v, 0,keyType.getVLength());
        
		EccP256CurvePoint p = new EccP256CurvePoint(v);
        //p.decode(new DataInputStream(new ByteArrayInputStream(v)));
        
		byte[] c = new byte[alg.getAlgorithm().getSymmetric().getKeyLength()];
		byte[] t = new byte[keyType.getOutputTagLength()];
		System.arraycopy(encryptedData, keyType.getVLength(), c, 0, alg.getAlgorithm().getSymmetric().getKeyLength());
		System.arraycopy(encryptedData, keyType.getVLength() + alg.getAlgorithm().getSymmetric().getKeyLength(), t, 0, keyType.getOutputTagLength());
		
		EciesP256EncryptedKey key = new EciesP256EncryptedKey(p,c,t);
		return new EncryptedDataEncryptionKey(keyType, key);
		 
	}


	/**
	 * Method to encrypt a symmetric key according to IEEE 1609.2 2017 specification.
	 *
	 * @param keyType the algorithm specification of the recipients public key.
	 * @param encryptionKey the recipients public key to encrypt to.
	 * @param symmetricKey the symmetric key to encrypt (Should be AES 128)
	 * @param p1 the deviation used as recipient information (SHA256 Hash of certificate or "" if no related certificate is available).
	 * @return a EncryptedDataEncryptionKey with v,c,t set.
	 * @throws IllegalArgumentException if supplied parameters where invalid.
	 * @throws GeneralSecurityException if problems occurred performing the encryption.
	 */
	public EncryptedDataEncryptionKey ieeeEceisEncryptSymmetricKey2017(EncryptedDataEncryptionKeyChoices keyType, PublicKey encryptionKey, SecretKey symmetricKey, byte[] p1) throws IllegalArgumentException, GeneralSecurityException, IOException{
		return ieeeEceisEncryptSymmetricKey2017(keyType,encryptionKey,symmetricKey,p1,null);
	}

	/**
	 * Method to encrypt a symmetric key according to IEEE 1609.2 2017 specification.
	 * <p>
	 *     <b>Important: this method should only be used when testing test vectors.</b>
	 * </p>
	 *
	 * @param keyType the algorithm specification of the recipients public key.
	 * @param encryptionKey the recipients public key to encrypt to.
	 * @param symmetricKey the symmetric key to encrypt (Should be AES 128)
	 * @param p1 the deviation used as recipient information (SHA256 Hash of certificate or "" if no related certificate is available).
	 * @param empericalPrivateKey use a specified empericalPrivate key, should only be used when testing predefiend test vector. And real use
	 *                            of ECIES encryption should specify null. Then a new key is generated for each call.
	 * @return a EncryptedDataEncryptionKey with v,c,t set.
	 * @throws IllegalArgumentException if supplied parameters where invalid.
	 * @throws GeneralSecurityException if problems occurred performing the encryption.
	 */
	public EncryptedDataEncryptionKey ieeeEceisEncryptSymmetricKey2017(EncryptedDataEncryptionKeyChoices keyType, PublicKey encryptionKey, SecretKey symmetricKey, byte[] p1, byte[] empericalPrivateKey) throws IllegalArgumentException, GeneralSecurityException{
		byte[] keyData = symmetricKey.getEncoded();
		ECDomainParameters domainParameters = keyType.getAlgorithm().getSignature().getECDomainParameters();

		int k_len = keyType.getAlgorithm().getSymmetric().getKeyLength();
		int p1_len = 32; //256/8
		assert (keyData.length == k_len) : "input k must be of octet length: " + k_len;
		assert p1.length == p1_len : "input P1 must be of octet length: " + p1_len;
		assert encryptionKey instanceof ECPublicKey;
		ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(encryptionKey);
		assert publicKeyParams.getQ().isValid() : "Public key is not on curve";

		ECPrivateKeyParameters empericalPrivateKeyParams=null;
		ECPublicKeyParameters empericalPublicKeyParams=null;

		if(empericalPrivateKey == null){
			EphemeralKeyPair ephemeralKeyPair = getEphemeralKeyPairGenerator(domainParameters).generate();
			empericalPrivateKeyParams = (ECPrivateKeyParameters) ephemeralKeyPair.getKeyPair().getPrivate();
			empericalPublicKeyParams = (ECPublicKeyParameters) ephemeralKeyPair.getKeyPair().getPublic();
		}else{
			BigInteger d = new BigInteger(Hex.toHexString(empericalPrivateKey),16);
			empericalPrivateKeyParams = new ECPrivateKeyParameters(d,domainParameters);
			ECPoint Q = new FixedPointCombMultiplier().multiply(domainParameters.getG(), d);
			empericalPublicKeyParams = new ECPublicKeyParameters(Q, domainParameters);
		}

		ECDHCBasicAgreement agreement = new ECDHCBasicAgreement();
		agreement.init(empericalPrivateKeyParams);
		BigInteger ss = agreement.calculateAgreement(publicKeyParams);
		byte[] SS = BigIntegers.asUnsignedByteArray(agreement.getFieldSize(), ss);

		int K1_len = keyType.getAlgorithm().getSymmetric().getKeyLength();
		int K2_len = 32; //256/8
		int dl = K1_len + K2_len;
		byte[] K1_K2 = new byte[dl];

		KDF2BytesGenerator kdf2BytesGenerator = new KDF2BytesGenerator(new SHA256Digest());
		kdf2BytesGenerator.init(new KDFParameters(SS, p1));
		kdf2BytesGenerator.generateBytes(K1_K2,0,dl);

		byte[] C = new byte[K1_len];
		for(int i = 0; i != K1_len; ++i) {
			C[i] = (byte)(keyData[i] ^ K1_K2[i]);
		}

		byte[] K2 = new byte[K2_len];
		System.arraycopy(K1_K2,K1_len,K2,0,K2_len);
		Mac1 mac1 = new Mac1(new SHA256Digest(),128);
		mac1.init(new KeyParameter(K2));
		mac1.update(C,0,C.length);
		byte[] T = new byte[mac1.getMacSize()];
		mac1.doFinal(T,0);

		byte[] V = empericalPublicKeyParams.getQ().getEncoded(true);
		EccP256CurvePoint vPubPoint = new EccP256CurvePoint(V);
		EciesP256EncryptedKey key = new EciesP256EncryptedKey(vPubPoint,C,T);
		return new EncryptedDataEncryptionKey(keyType, key);
	}

	/**
	 * Help method to create a ephemeral key pair generator used to generate a unique key for
	 * each ECIES encryption.
	 * @param domainParameters the EC curve domain parameters used.
	 * @return a new EphemeralKeyPairGenerator
	 */
	private EphemeralKeyPairGenerator getEphemeralKeyPairGenerator(ECDomainParameters domainParameters){
		ECKeyGenerationParameters ecKeyGenerationParameters = new ECKeyGenerationParameters(domainParameters, new SecureRandom());
		ECKeyPairGenerator ecKeyPairGenerator = new ECKeyPairGenerator();
		ecKeyPairGenerator.init(ecKeyGenerationParameters);
		EphemeralKeyPairGenerator ephemeralKeyPairGenerator = new EphemeralKeyPairGenerator(ecKeyPairGenerator, new KeyEncoder()
		{
			public byte[] getEncoded(AsymmetricKeyParameter keyParameter)
			{
				return ((ECPublicKeyParameters)keyParameter).getQ().getEncoded(true);
			}
		});
		return ephemeralKeyPairGenerator;
	}

	/**
	 * Method to decrypt symmetric key using the 1609.2 2017 defined ECIES encryption scheme.
	 * @param encryptedDataEncryptionKey the type of encryption key.
	 * @param decryptionKey the receiver's private key.
	 * @param p1 the deviation used as recipient information (SHA256 Hash of certificate or "" if no related certificate is available).
	 * @return the decrypted AES symmetric key.
	 * @throws InvalidKeyException if supplied private key was invalid
	 * @throws IllegalArgumentException if invalid arguments where specified.
	 * @throws InvalidKeySpecException if invalid key specification was given.
	 */
	protected Key ieeeEceisDecryptSymmetricKey2017(EncryptedDataEncryptionKey encryptedDataEncryptionKey, PrivateKey decryptionKey, byte[] p1) throws InvalidKeyException, IllegalArgumentException, InvalidKeySpecException {
		ECDomainParameters domainParameters = encryptedDataEncryptionKey.getType().getAlgorithm().getSignature().getECDomainParameters();

		int k_len = encryptedDataEncryptionKey.getType().getAlgorithm().getSymmetric().getKeyLength();
		int p1_len = 32; //256/8
		EciesP256EncryptedKey eciesP256EncryptedKey = (EciesP256EncryptedKey) encryptedDataEncryptionKey.getValue();
		assert (eciesP256EncryptedKey.getC().length== k_len) : "input C must be of octet length: " + k_len;
		assert p1.length == p1_len : "input P1 must be of octet length: " + p1_len;
		assert eciesP256EncryptedKey.getV().getType() == EccP256CurvePointChoices.compressedy0 || eciesP256EncryptedKey.getV().getType() == EccP256CurvePointChoices.compressedy1 : "V EC Point must be stored in compressed format.";
		assert decryptionKey instanceof ECPrivateKey;
		ECPrivateKeyParameters rPrivKeyParameter = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(decryptionKey);

		BCECPublicKey cPubKey = (BCECPublicKey) decodeEccPoint(encryptedDataEncryptionKey.getType(),eciesP256EncryptedKey.getV());
		byte[] V = cPubKey.getQ().getEncoded(true);
		ECPublicKeyParameters vPubParam = new ECPublicKeyParameters(domainParameters.getCurve().decodePoint(V), domainParameters);

		ECDHCBasicAgreement agreement = new ECDHCBasicAgreement();
		agreement.init(rPrivKeyParameter);
		BigInteger ss = agreement.calculateAgreement(vPubParam);
		byte[] SS = BigIntegers.asUnsignedByteArray(agreement.getFieldSize(), ss);

		int K1_len = encryptedDataEncryptionKey.getType().getAlgorithm().getSymmetric().getKeyLength();
		int K2_len = 32; //256/8
		int dl = K1_len + K2_len;
		byte[] K1_K2 = new byte[dl];

		KDF2BytesGenerator kdf2BytesGenerator = new KDF2BytesGenerator(new SHA256Digest());
		kdf2BytesGenerator.init(new KDFParameters(SS, p1));
		kdf2BytesGenerator.generateBytes(K1_K2,0,dl);

		byte[] C = eciesP256EncryptedKey.getC();
		byte[] K2 = new byte[K2_len];
		System.arraycopy(K1_K2,K1_len,K2,0,K2_len);
		Mac1 mac1 = new Mac1(new SHA256Digest(),128);
		mac1.init(new KeyParameter(K2));
		mac1.update(C,0,C.length);
		byte[] T = new byte[mac1.getMacSize()];
		mac1.doFinal(T,0);

		if(!Arrays.equals(T, eciesP256EncryptedKey.getT())){
			throw new InvalidKeyException("Invalied ECIES Authentication MAC does not match");
		}

		byte[] keyData = new byte[K1_len];
		for(int i = 0; i != K1_len; ++i) {
			keyData[i] = (byte)(C[i] ^ K1_K2[i]);
		}

		return new SecretKeySpec(keyData,"AES");
	}

	/**
	 * Help method to perform a ECIES decryption of a symmetric key using the ITS protocol version 1 specification. 
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
	protected Key itsEceisDecryptSymmetricKeyVer1(EciesNistP256EncryptedKey eciesNistP256EncryptedKey, PrivateKey decryptionKey) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IllegalArgumentException, InvalidKeySpecException, IOException{
		if(eciesNistP256EncryptedKey.getPublicKeyAlgorithm() != PublicKeyAlgorithm.ecies_nistp256){
			throw new IllegalArgumentException("Unsupported encryption public key algorithm: " + eciesNistP256EncryptedKey.getPublicKeyAlgorithm() );
		}
		
		IESCipher eCIESCipher = new ECIES();
		eCIESCipher.engineInit(Cipher.DECRYPT_MODE, decryptionKey, new IESParameterSpec(null, null, 128),secureRandom);
				
		byte[] encryptedData = new byte[ECIES_NIST_P256_V_LENGTH_VER1 + eciesNistP256EncryptedKey.getPublicKeyAlgorithm().getRelatedSymmetricAlgorithm().getKeyLength() + EciesNistP256EncryptedKey.VER1_OUTPUT_TAG_LENGTH];
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dis = new DataOutputStream(baos);
		
		eciesNistP256EncryptedKey.getV().encode(dis);
		baos.close();
		System.arraycopy(baos.toByteArray(), 0, encryptedData, 0, ECIES_NIST_P256_V_LENGTH_VER1);
		System.arraycopy(eciesNistP256EncryptedKey.getC(), 0, encryptedData, ECIES_NIST_P256_V_LENGTH_VER1, eciesNistP256EncryptedKey.getPublicKeyAlgorithm().getRelatedSymmetricAlgorithm().getKeyLength());
		System.arraycopy(eciesNistP256EncryptedKey.getT(), 0, encryptedData, ECIES_NIST_P256_V_LENGTH_VER1+eciesNistP256EncryptedKey.getPublicKeyAlgorithm().getRelatedSymmetricAlgorithm().getKeyLength(), EciesNistP256EncryptedKey.VER1_OUTPUT_TAG_LENGTH);
		
		
		
		byte[] decryptedData = eCIESCipher.engineDoFinal(encryptedData, 0, encryptedData.length);

		return new SecretKeySpec(decryptedData, "AES");
	}
	
	/**
	 * Help method to perform a ECIES decryption of a symmetric key using the ITS protocol version 2 specification. 
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
	protected Key itsEciesDecryptSymmetricKeyVer2(EciesNistP256EncryptedKey eciesNistP256EncryptedKey, PrivateKey decryptionKey) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IllegalArgumentException, InvalidKeySpecException, IOException{
		if(eciesNistP256EncryptedKey.getPublicKeyAlgorithm() != PublicKeyAlgorithm.ecies_nistp256){
			throw new IllegalArgumentException("Unsupported encryption public key algorithm: " + eciesNistP256EncryptedKey.getPublicKeyAlgorithm() );
		}
		
		IESCipher eCIESCipher = new IEEE1609Dot2ECIES();
		eCIESCipher.engineInit(Cipher.DECRYPT_MODE, decryptionKey, new IESParameterSpec(null, null, 128,-1, null, true),secureRandom);
				
		byte[] encryptedData = new byte[ECIES_NIST_P256_V_LENGTH_VER2 + eciesNistP256EncryptedKey.getPublicKeyAlgorithm().getRelatedSymmetricAlgorithm().getKeyLength() + EciesNistP256EncryptedKey.VER2_OUTPUT_TAG_LENGTH];
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dis = new DataOutputStream(baos);
		
		eciesNistP256EncryptedKey.getV().encode(dis);
		baos.close();
		System.arraycopy(baos.toByteArray(), 0, encryptedData, 0, ECIES_NIST_P256_V_LENGTH_VER2);
		System.arraycopy(eciesNistP256EncryptedKey.getC(), 0, encryptedData, ECIES_NIST_P256_V_LENGTH_VER2, eciesNistP256EncryptedKey.getPublicKeyAlgorithm().getRelatedSymmetricAlgorithm().getKeyLength());
		System.arraycopy(eciesNistP256EncryptedKey.getT(), 0, encryptedData, ECIES_NIST_P256_V_LENGTH_VER2+eciesNistP256EncryptedKey.getPublicKeyAlgorithm().getRelatedSymmetricAlgorithm().getKeyLength(), EciesNistP256EncryptedKey.VER2_OUTPUT_TAG_LENGTH);
		
		
		
		byte[] decryptedData = eCIESCipher.engineDoFinal(encryptedData, 0, encryptedData.length);

		return new SecretKeySpec(decryptedData, "AES");
	}
	
	/**
	 * Help method to perform a ECIES decryption of a symmetric key. 
	 * 
	 * @param encryptedDataEncryptionKey the EncryptedDataEncryptionKey to decrypt
	 * @param decryptionKey the receiptients private key
	 * @param alg the related algorithm to use
	 * @param eciesDeviation to use as P1 parameter.
	 * @return a decrypted symmetric key.
	 * 
	 * @throws IllegalArgumentException if arguments where invalid or algorithm not supported.
	 * @throws GeneralSecurityException if internal problems occurred decrypting key.
	 * @throws IOException if communication problem occurred with underlying systems.
	 */
	@Override
	public SecretKey ieeeECEISDecryptSymmetricKey(EncryptedDataEncryptionKey encryptedDataEncryptionKey, PrivateKey decryptionKey, AlgorithmIndicator alg, byte[] eciesDeviation) throws IllegalArgumentException, GeneralSecurityException, IOException{
		try{
			EncryptedDataEncryptionKeyChoices keyType = encryptedDataEncryptionKey.getType();
			IESCipher eCIESCipher = new IEEE1609Dot2ECIES();
			eCIESCipher.engineInit(Cipher.DECRYPT_MODE, decryptionKey, new IESParameterSpec(eciesDeviation, null, 128,-1, null, true),secureRandom);

			byte[] encryptedData = new byte[keyType.getVLength() + alg.getAlgorithm().getSymmetric().getKeyLength() + keyType.getOutputTagLength()];


			EciesP256EncryptedKey eciesP256EncryptedKey = (EciesP256EncryptedKey) encryptedDataEncryptionKey.getValue();
			ECPublicKey pubKey = (ECPublicKey) decodeEccPoint(alg, eciesP256EncryptedKey.getV());
			BCECPublicKey bcPubKey = convertECPublicKeyToBCECPublicKey(alg, pubKey);

			System.arraycopy(bcPubKey.getQ().getEncoded(true), 0, encryptedData, 0, keyType.getVLength());
			System.arraycopy(eciesP256EncryptedKey.getC(), 0, encryptedData, keyType.getVLength(), alg.getAlgorithm().getSymmetric().getKeyLength());
			System.arraycopy(eciesP256EncryptedKey.getT(), 0, encryptedData, keyType.getVLength()+alg.getAlgorithm().getSymmetric().getKeyLength(), keyType.getOutputTagLength());

			byte[] decryptedData = eCIESCipher.engineDoFinal(encryptedData, 0, encryptedData.length);
			return new SecretKeySpec(decryptedData, "AES");
		}catch(BadPaddingException e){
			throw new InvalidKeyException("Error decrypting symmetric key using supplied private key: " + e.getMessage(), e);
		}
	}
	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#symmetricEncrypt(AlgorithmIndicator, byte[], Key, byte[])
	 */
	@Override
	public byte[] symmetricEncrypt(AlgorithmIndicator alg, byte[] data, Key symmetricKey, byte[] nounce) throws IllegalArgumentException, GeneralSecurityException{

		Cipher c = getSymmetricCipher(alg, true);
	    c.init(Cipher.ENCRYPT_MODE, symmetricKey);
	    
		return c.doFinal(data);	
	}

	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#symmetricEncrypt(AlgorithmIndicator, byte[], Key, byte[])
	 */
	public byte[] symmetricEncryptIEEE1609_2_2017(AlgorithmIndicator alg, byte[] data, byte[] symmetricKey, byte[] nounce) throws IllegalArgumentException, InvalidCipherTextException {
		if(alg.getAlgorithm().getSymmetric() == Symmetric.aes128Ccm) {
			CCMBlockCipher ccmBlockCipher = new CCMBlockCipher(new AESEngine());

			AEADParameters parameterSpec = new AEADParameters(new KeyParameter(symmetricKey), 128, nounce, null); //128 bit auth tag length
			ccmBlockCipher.init(true, parameterSpec);

			byte[] outData = new byte[ccmBlockCipher.getOutputSize(data.length)];
			int outputLen = ccmBlockCipher.processBytes(data, 0, data.length,
					outData, 0);
			ccmBlockCipher.doFinal(outData, outputLen);

			return outData;
		}
		throw new IllegalArgumentException("Unsupported symmetric encryption algorithm specified: " + alg.getAlgorithm().getSymmetric());
	}

	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#symmetricEncrypt(AlgorithmIndicator, byte[], Key, byte[])
	 */
	public byte[] symmetricDecryptIEEE1609_2_2017(AlgorithmIndicator alg, byte[] data, byte[] symmetricKey, byte[] nounce) throws IllegalArgumentException,  InvalidCipherTextException {
		if(alg.getAlgorithm().getSymmetric() == Symmetric.aes128Ccm) {
			CCMBlockCipher ccmBlockCipher = new CCMBlockCipher(new AESEngine());

			AEADParameters parameterSpec = new AEADParameters(new KeyParameter(symmetricKey), 128, nounce, null); //128 bit auth tag length
			ccmBlockCipher.init(false, parameterSpec);

			byte[] outData = new byte[ccmBlockCipher.getOutputSize(data.length)];
			int outputLen = ccmBlockCipher.processBytes(data, 0, data.length,
					outData, 0);
			ccmBlockCipher.doFinal(outData, outputLen);

			return outData;
		}
		throw new IllegalArgumentException("Unsupported symmetric encryption algorithm specified: " + alg.getAlgorithm().getSymmetric());
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#symmetricDecrypt(AlgorithmIndicator, byte[], Key, byte[])
	 */
	@Override
	public byte[] symmetricDecrypt(AlgorithmIndicator alg, byte[] data, Key symmetricKey, byte[] nounce) throws IllegalArgumentException, GeneralSecurityException{
		
		Cipher c = getSymmetricCipher(alg, false);
	    c.init(Cipher.DECRYPT_MODE, symmetricKey, new IvParameterSpec(nounce));
	    
		return c.doFinal(data);	
	}
	
	private Map<String, Cipher> chiphers = new HashMap<String, Cipher>();
	
	protected Cipher getSymmetricCipher(AlgorithmIndicator alg, boolean encrypt) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{
		Cipher retval = null;
		Symmetric symmetricAlgorithm = alg.getAlgorithm().getSymmetric();
		
		if(symmetricAlgorithm != Symmetric.aes128Ccm){
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
		    	  chiphers.put(symmetricAlgorithm + "_decrypt", retval); 
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
			if(headerFields.get(i).getHeaderFieldType().getOrder(secureMessage.getProtocolVersion()) > headerField.getHeaderFieldType().getOrder(secureMessage.getProtocolVersion())){
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
	 * Method to convert a EC public key to a BCECPublicKey
	 * @param alg specifying the related curve used.
	 * @param ecPublicKey key to convert
	 * @return a BCECPublicKey
	 * @throws InvalidKeySpecException if supplied key was invalid.
	 */
	@Override
	public BCECPublicKey toBCECPublicKey(AlgorithmIndicator alg, java.security.interfaces.ECPublicKey ecPublicKey) throws InvalidKeySpecException{
		if(ecPublicKey instanceof BCECPublicKey){
			return (BCECPublicKey) ecPublicKey;
		}
		
		org.bouncycastle.math.ec.ECPoint ecPoint = EC5Util.convertPoint(getECCurve(alg), ecPublicKey.getW(), false);
		ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, getECParameterSpec(alg));
		
		return (BCECPublicKey) keyFact.generatePublic(keySpec);

	}

	/**
	 * Returns the related EC domain parameters for given algorithm.
	 * @param alg
	 * @return related EC domain parameters for given algorithm.
	 */
	@Override
	public ECParameterSpec getECParameterSpec(AlgorithmIndicator alg){
		if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaNistP256){
			return ecNistP256Spec;
		}
		if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaBrainpoolP256r1){
			return brainpoolp256r1Spec;
		}
		throw new IllegalArgumentException("Unsupported EC Algorithm: " + alg);
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#reconstructImplicitPrivateKey(org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate, BigInteger, AlgorithmIndicator, PrivateKey, PublicKey, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate)
	 */
	@Override
	public PrivateKey reconstructImplicitPrivateKey(
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate cert,
			BigInteger r,
			AlgorithmIndicator alg,
			PrivateKey Ku,
			PublicKey signerPublicKey,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signerCertificate)
			throws IOException, IllegalArgumentException, SignatureException {
		return ecqvHelper.certReceiption(cert, r, alg, (ECPrivateKey) Ku, (ECPublicKey) signerPublicKey, signerCertificate);
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
			List<Encodable> recipients) throws IllegalArgumentException, IOException{
		HashedId8 hashId = new HashedId8(receiverCertificate.getEncoded());
		for(Encodable n : recipients){
			RecipientInfo ri = (RecipientInfo) n;
			if(ri.getCertId().equals(hashId)){
				return ri;
			}
		}
		throw new IllegalArgumentException("Error no recipient info found in header matching certificate with hashId: " + hashId.toString());
	}
	
	
	protected ECCurve getECCurve(AlgorithmIndicator alg){
		if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaNistP256){
			return ecNistP256Curve;
		}
		if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaBrainpoolP256r1){
			return brainpoolp256r1;
		}
		throw new IllegalArgumentException("Unsupported EC Algorithm: " + alg);
	}
	

	
	protected ECPublicKey getECPublicKeyFromECPoint(AlgorithmIndicator alg, ECPoint eCPoint) throws InvalidKeySpecException{
		ECPublicKeySpec spec = new ECPublicKeySpec(eCPoint, getECParameterSpec(alg));
		return (ECPublicKey) keyFact.generatePublic(spec);
	}


	

	protected BCECPublicKey convertECPublicKeyToBCECPublicKey(AlgorithmIndicator alg, java.security.interfaces.ECPublicKey ecPublicKey) throws InvalidKeySpecException{
		if(ecPublicKey instanceof BCECPublicKey){
			return (BCECPublicKey) ecPublicKey;
		}
		
		org.bouncycastle.math.ec.ECPoint ecPoint = EC5Util.convertPoint(getECCurve(alg), ecPublicKey.getW(), false);
		ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, getECParameterSpec(alg));
		
		return (BCECPublicKey) keyFact.generatePublic(keySpec);

	}
	
	
	public EccPoint getVerificationKey(Certificate cert) throws IllegalArgumentException {
		for(SubjectAttribute attr : cert.getSubjectAttributes()){
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
		if(certificate.getVersion() == Certificate.CERTIFICATE_VERSION_1){
		  EncodeHelper.encodeVariableSizeVector(dos, certificate.getSignerInfos());
		}else{
			certificate.getSignerInfos().get(0).encode(dos);	
		}
		certificate.getSubjectInfo().encode(dos);
		EncodeHelper.encodeVariableSizeVector(dos, certificate.getSubjectAttributes());
		EncodeHelper.encodeVariableSizeVector(dos, certificate.getValidityRestrictions());
		return baos.toByteArray();
	}
	
	
	protected byte[] serializeDataToBeSignedInSecuredMessage(SecuredMessage message, Signature signature) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		dos.write(message.getProtocolVersion());
		if(message.getProtocolVersion() == SecuredMessage.PROTOCOL_VERSION_1){
		  dos.write(message.getSecurityProfile());
		}
		
		EncodeHelper.encodeVariableSizeVector(dos, message.getHeaderFields());
		if(message.getProtocolVersion() == SecuredMessage.PROTOCOL_VERSION_1){
		  serializeTotalPayloadSize(dos, message.getPayloadFields());
		}
		for(Payload pl : message.getPayloadFields()){
			if(pl.getPayloadType() == PayloadType.encrypted || pl.getPayloadType() == PayloadType.unsecured){
				// if payload shouldn't be included in the signature should only the type and length be included
			    dos.write(pl.getPayloadType().getByteValue());
			    IntX size = new IntX(pl.getData().length);
			    size.encode(dos);
			}else{
				pl.encode(dos);
			}
		}
				
		// Serialize all trailer fields until a signature is found
		serializeTotalSignedTrailerLength(dos, message.getTrailerFields(), signature);
		if(message.getTrailerFields() == null || message.getTrailerFields().size() == 0){
			dos.writeByte(TrailerFieldType.signature.getByteValue());
		}else{
			for(TrailerField tf : message.getTrailerFields()){
				if(tf.getTrailerFieldType() != TrailerFieldType.signature){
					tf.encode(dos);
				}else{
					// Don't calculate any more fields in the signature.
					dos.writeByte(TrailerFieldType.signature.getByteValue());
					break;
				}
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


	protected void serializeTotalPayloadSize(DataOutputStream out, List<? extends Encodable> variableSizeVector) throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);    		 
		for(Encodable next: variableSizeVector){
			next.encode(dos);
		}
		byte[] data = baos.toByteArray();
		IntX size = new IntX(data.length);
		size.encode(out);
	}
	

	protected void serializeTotalSignedTrailerLength(DataOutputStream out, List<TrailerField> variableSizeVector, Signature signature) throws IOException, IllegalArgumentException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);  		
		for(TrailerField next: variableSizeVector){
			if(next.getTrailerFieldType() == TrailerFieldType.signature){
				break;
			}
			next.encode(dos);
		}
		byte[] data = baos.toByteArray();
		int length = data.length;
		
		length += calculateSignatureLength(signature);
		IntX size = new IntX(length);
		size.encode(out);
	}

	protected int calculateSignatureLength(Signature signature) throws IllegalArgumentException {
		if(signature.getPublicKeyAlgorithm() == PublicKeyAlgorithm.ecdsa_nistp256_with_sha256){			
			if(signature.getSignatureValue().getR().getEccPointType() == EccPointType.uncompressed){
				return 2 + (3* signature.getPublicKeyAlgorithm().getFieldSize()) + 1; // public key alg type (1 byte) + EccPointType (1 byte) + R (2 * (x+y) field size in bytes) + s (field size in bytes) + signature trailer field type
			}
			return 2 + (2* signature.getPublicKeyAlgorithm().getFieldSize()) + 1; // public key alg type (1 byte) + EccPointType (1 byte) + R (field size in bytes) + s (field size in bytes)  + signature trailer field type
		}
		throw new IllegalArgumentException("Error unsupported digital signature algorithm " + signature.getPublicKeyAlgorithm());
	}
	
	protected SignatureChoices getSignatureChoice(
			org.certificateservices.custom.c2x.common.crypto.Algorithm.Signature sigAlg) {
		switch (sigAlg) {
		case ecdsaNistP256:
			return SignatureChoices.ecdsaNistP256Signature;
		case ecdsaBrainpoolP256r1:
		default:
			return SignatureChoices.ecdsaBrainpoolP256r1Signature;
		}
	}
	
	protected AlgorithmIndicator  getSignatureAlgorithm(SignatureChoices sigChoice) {
		switch (sigChoice) {
		case ecdsaNistP256Signature:
			return PublicVerificationKeyChoices.ecdsaNistP256;
		case ecdsaBrainpoolP256r1Signature:
		default:
			return PublicVerificationKeyChoices.ecdsaBrainpoolP256r1;
		}
	}


	
	protected boolean verifyExplicitCertSignature(
			byte[] message,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signature,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signCert,
			EccP256CurvePoint pubVerKey) throws IllegalArgumentException,
			SignatureException, IOException {
		 
		AlgorithmIndicator alg = getSignatureAlgorithm(signature.getType());
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new IllegalArgumentException("Error no signature algorithm specified");
		}
		try{
			return verifySignatureDigest(genIEEECertificateDigest(alg,message, signCert), signature, (PublicKey) decodeEccPoint(alg, pubVerKey));
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
	}
	
	protected boolean verifyImplicitCertSignature(
			byte[] message,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signature,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signCert,
			PublicKey signerPublicKey) throws IllegalArgumentException,
			SignatureException, IOException {
		 
		AlgorithmIndicator alg = getSignatureAlgorithm(signature.getType());
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new IllegalArgumentException("Error no signature algorithm specified");
		}
		try{
			return verifySignatureDigest(genIEEECertificateDigest(alg,message, signCert), signature, signerPublicKey);
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
	}


	/**
	 * Specific ECIES configuration to fullfill both ITS and IEEE standards.
	 * 
	 * 
	 *
	 */
    static public class IEEE1609Dot2ECIES
    extends IESCipher
{
    public IEEE1609Dot2ECIES()
    {
        super(new IESEngine(new ECDHCBasicAgreement(),
            new KDF2BytesGenerator(new SHA256Digest()),
            new Mac1(new SHA256Digest(),128)));
    }


}



}
