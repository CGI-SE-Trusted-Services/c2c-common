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
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
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
import java.util.HashMap;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.certificateservices.custom.c2x.its.datastructs.SerializationHelper;
import org.certificateservices.custom.c2x.its.datastructs.StructSerializer;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.EcdsaSignature;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttribute;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType;
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderField;
import org.certificateservices.custom.c2x.its.datastructs.msg.HeaderFieldType;
import org.certificateservices.custom.c2x.its.datastructs.msg.Payload;
import org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType;
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
		}catch(InvalidAlgorithmParameterException e){
			throw new NoSuchAlgorithmException("InvalidAlgorithmParameterException: " + e.getMessage(),e);
		}
	}
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#signSecureMessage(SecuredMessage, PublicKeyAlgorithm, PrivateKey)
	 */
	@Override
	public SecuredMessage signSecureMessage(SecuredMessage secureMessage, PublicKeyAlgorithm alg,
			PrivateKey privateKey) throws IllegalArgumentException, SignatureException, IOException {	
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
	public boolean verifySecuredMessage(SecuredMessage message)
			throws IllegalArgumentException, SignatureException, IOException {
		Certificate signerCert = findFirstValidCertificateInMessage(message);
		return verifySecuredMessage(message, signerCert);
	}

	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#verifySecuredMessage(SecuredMessage, Certificate)
	 */
	@Override
	public boolean verifySecuredMessage(SecuredMessage message,
			Certificate signerCert) throws IllegalArgumentException,
			SignatureException, IOException {
		Signature signature = findSignatureInMessage(message);
		byte[] msgData = serializeDataToBeSignedInSecuredMessage(message, signature);
	
		
		return verifySignature(msgData, signature, signerCert);
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
	
	/**
	 * @see org.certificateservices.custom.c2x.its.crypto.CryptoManager#disconnect()
	 */
	@Override
	public void disconnect() throws IOException {
		
		
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
