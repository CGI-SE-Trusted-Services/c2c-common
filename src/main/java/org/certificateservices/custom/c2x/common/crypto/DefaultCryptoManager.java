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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.crypto.EphemeralKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyEncoder;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.EncodeHelper;
import org.certificateservices.custom.c2x.common.crypto.Algorithm.Hash;
import org.certificateservices.custom.c2x.common.crypto.Algorithm.Symmetric;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Default implementation of ITS CryptoManager with support for public key algorithms: ecdsa_nistp256_with_sha256 and ecies_nistp256
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class DefaultCryptoManager implements Ieee1609Dot2CryptoManager {
	
   
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
    protected ECCurve brainpoolP384r1 = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP384r1).getCurve();
	protected KeyFactory keyFact;
	protected MessageDigest sha256Digest;
	protected MessageDigest sha384Digest;
	protected ECQVHelper ecqvHelper;
	
	protected String provider;
	

	/**
	 * Initialized Bouncycastle and it's specific key factories
	 */
	@Override
	public void setupAndConnect(CryptoManagerParams params) throws BadArgumentException, NoSuchAlgorithmException, NoSuchProviderException, IOException, BadCredentialsException, SignatureException{
		if(!(params instanceof DefaultCryptoManagerParams)){
			throw new BadArgumentException("Invalid type of CryptoManagerParams given, expected DefaultCryptoManagerParams");
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
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#genNounce(AlgorithmIndicator)
	 */
	@Override
	public byte[] genNounce(AlgorithmIndicator alg) throws BadArgumentException{
		if( alg.getAlgorithm().getSymmetric() == null){
			throw new BadArgumentException("Error algorithm scheme doesn't support symmetric encryption");
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
	public SecretKey constructSecretKey(AlgorithmIndicator alg, byte[] keyData) throws BadArgumentException, GeneralSecurityException{
		if(alg.getAlgorithm().getSymmetric() != Symmetric.aes128Ccm){
			throw new BadArgumentException("Count construct secret key from unsupported algorithm: " + alg);
		}
		return new SecretKeySpec(keyData, "AES");
	}

	
	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#signMessageDigest(byte[], AlgorithmIndicator, PrivateKey)
	 */
	@Override
	public org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signMessageDigest(
			byte[] digest, AlgorithmIndicator alg, PrivateKey privateKey)
			throws BadArgumentException, SignatureException, IOException {
		
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new BadArgumentException("Error no signature algorithm specified");
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

			if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaBrainpoolP384r1) {
                return new org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature(
                        getSignatureChoice(sigAlg), new EcdsaP384Signature(new EccP384CurvePoint(r),
                        baos.toByteArray()));
            }
            return new org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature(
                    getSignatureChoice(sigAlg), new EcdsaP256Signature(new EccP256CurvePoint(r),
                    baos.toByteArray()));

		}catch(Exception e){
			if(e instanceof BadArgumentException){
				throw (BadArgumentException) e;
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
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#signMessage(byte[], AlgorithmIndicator, PrivateKey, CertificateType, Certificate)
	 */
	@Override
	public org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signMessage(
			byte[] message, AlgorithmIndicator alg, PrivateKey privateKey,
			CertificateType certType,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signCert)
			throws BadArgumentException, SignatureException, IOException {
		
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new BadArgumentException("Error no signature algorithm specified");
		}
		
		try{
			  return signMessageDigest(genIEEECertificateDigest(alg, message, signCert), alg, privateKey);
		}catch(Exception e){
			if(e instanceof BadArgumentException){
				throw (BadArgumentException) e;
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
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#verifySignatureDigest(byte[], org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature, PublicKey)
	 */
	@Override
	public boolean verifySignatureDigest(
			byte[] digest,
			Signature signature,
			PublicKey publicKey) throws BadArgumentException,
			SignatureException, IOException {
		 
		AlgorithmIndicator alg = getSignatureAlgorithm(signature.getType());
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new BadArgumentException("Error no signature algorithm specified");
		}
		
		try{
			BigInteger r = getSignatureRValue(sigAlg, signature);
			byte[] signatureS = getSignatureSValue(sigAlg, signature);

			ASN1Integer asn1R = new ASN1Integer(r);		    
			ASN1Integer asn1S = new ASN1Integer(EncodeHelper.readFixedFieldSizeKey(sigAlg.getFieldSize(), new ByteArrayInputStream(signatureS)));
			DLSequence dLSequence = new DLSequence(new ASN1Encodable[]{asn1R, asn1S});
			byte[] dERSignature = dLSequence.getEncoded();

			java.security.Signature sig = java.security.Signature.getInstance("NONEwithECDSA", provider); 
			sig.initVerify(publicKey);
			sig.update(digest);
			return sig.verify(dERSignature);
		}catch(Exception e){
			if(e instanceof BadArgumentException){
				throw (BadArgumentException) e;
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

	protected BigInteger getSignatureRValue(Algorithm.Signature sigAlg, Signature signature){
	    if(sigAlg == Algorithm.Signature.ecdsaBrainpoolP384r1){
            EcdsaP384Signature ecdsaSignature = (EcdsaP384Signature) signature.getValue();
            EccP384CurvePoint xPoint = ecdsaSignature.getR();
            return new BigInteger(1,((COEROctetStream) xPoint.getValue()).getData());
        }
        EcdsaP256Signature ecdsaSignature = (EcdsaP256Signature) signature.getValue();
        EccP256CurvePoint xPoint = ecdsaSignature.getR();
        return new BigInteger(1,((COEROctetStream) xPoint.getValue()).getData());
    }


    protected byte[] getSignatureSValue(Algorithm.Signature sigAlg, Signature signature){
        if(sigAlg == Algorithm.Signature.ecdsaBrainpoolP384r1) {
            EcdsaP384Signature ecdsaSignature = (EcdsaP384Signature) signature.getValue();
            return ecdsaSignature.getS();
        }
        EcdsaP256Signature ecdsaSignature = (EcdsaP256Signature) signature.getValue();
        return ecdsaSignature.getS();
    }
	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#verifySignature(byte[], org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate)
	 */
	@Override
	public boolean verifySignature(
			byte[] message,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signature,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signerCert)
			throws BadArgumentException, SignatureException, IOException {
		if(signerCert.getType() == CertificateType.explicit){
			PublicVerificationKey pubVerKey = (PublicVerificationKey) signerCert.getToBeSigned().getVerifyKeyIndicator().getValue();
			return verifySignature(message, signature, signerCert, pubVerKey);
		}else{
			throw new BadArgumentException("Implicit certificates not supported by this method");
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
			throws BadArgumentException, SignatureException, IOException {
		if(signerCert.getType() == CertificateType.explicit){
			return verifyExplicitCertSignature(message, signature, signerCert, signedPublicKey);
		}else{
			return verifyImplicitCertSignature(message, signature,signerCert,signedPublicKey);
		}
	}

	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#verifySelfSignedSignature(byte[], org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature, PublicKey)
	 */
	@Override
	public boolean verifySelfSignedSignature(
			byte[] message,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signature,
			PublicKey signedPublicKey)
			throws BadArgumentException, SignatureException, IOException {
			return verifyExplicitCertSignature(message, signature, null, signedPublicKey);
	}
	
	/**
	 *  {@link org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#verifyCertificate(org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate)}
	 */
	@Override
	public boolean verifyCertificate(
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate certificate,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signerCertificate)
			throws BadArgumentException, SignatureException, IOException {
		if(certificate.equals(signerCertificate)){
			return verifySignature(certificate.getToBeSigned().getEncoded(), certificate.getSignature(),null, (PublicVerificationKey) certificate.getToBeSigned().getVerifyKeyIndicator().getValue());
		}else{
			return verifySignature(certificate.getToBeSigned().getEncoded(), certificate.getSignature(), signerCertificate);
		}
		
	}
	

	protected boolean verifySignature(
			byte[] message,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signature,
            org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signerCertificate,
			PublicVerificationKey publicVerificationKey)
			throws BadArgumentException, SignatureException, IOException {
		try {
			PublicKey publicKey = (PublicKey) decodeEccPoint(publicVerificationKey.getType(), (EccCurvePoint) publicVerificationKey.getValue());
			return verifyExplicitCertSignature(message, signature, signerCertificate, publicKey);
		}catch(InvalidKeySpecException e){
			throw new SignatureException("Error verifying signature, invalid key spec: " + e.getMessage());
		}
	}


	/**
	 * Supports ECDSA P256, BrainPool P256r1 and BrainPool P384r1
	 * 
	 * @see org.certificateservices.custom.c2x.common.crypto.CryptoManager#generateKeyPair(AlgorithmIndicator)
	 */
	public KeyPair generateKeyPair(AlgorithmIndicator alg) throws BadArgumentException{
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new BadArgumentException("Error invalid algorithm when generating key pair: "+ alg);
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
		throw new BadArgumentException("Error unsupported algorithm when generating key pair: " + sigAlg);
	}
	
	/**
	 * Supports acm aes 128
	 * 
	 * @see org.certificateservices.custom.c2x.common.crypto.CryptoManager#generateSecretKey(AlgorithmIndicator)
	 */
	@Override
	public SecretKey generateSecretKey(AlgorithmIndicator alg) throws BadArgumentException{
		Algorithm.Symmetric symAlg = alg.getAlgorithm().getSymmetric();
		if(symAlg == null){
			throw new BadArgumentException("Error invalid algorithm when generating secret key: "+ alg);
		}
		if(symAlg == Algorithm.Symmetric.aes128Ccm){
			return aES128Generator.generateKey();
		}
		throw new BadArgumentException("Error unsupported algorithm when generating secret key: " + symAlg);
	}

	
	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager
	 */
	@Override
	public EccP256CurvePoint encodeEccPoint(AlgorithmIndicator alg,
			EccP256CurvePointChoices type, PublicKey publicKey)
			throws BadArgumentException, InvalidKeySpecException {
		if(! (publicKey instanceof java.security.interfaces.ECPublicKey)){
			throw new BadArgumentException("Only ec public keys are supported, not " + publicKey.getClass().getSimpleName());
		}
		BCECPublicKey bcPub = toBCECPublicKey(alg, (java.security.interfaces.ECPublicKey) publicKey);

		try {
			if (type == EccP256CurvePointChoices.uncompressed) {
				return new EccP256CurvePoint(bcPub.getW().getAffineX(), bcPub.getW().getAffineY());
			}
			if (type == EccP256CurvePointChoices.compressedy0 || type == EccP256CurvePointChoices.compressedy1) {
				return new EccP256CurvePoint(bcPub.getQ().getEncoded(true));
			}
			if (type == EccP256CurvePointChoices.xonly) {
				return new EccP256CurvePoint(bcPub.getW().getAffineX());
			}
		}catch(IOException e){
			throw new BadArgumentException("Invalid public key specified: " + e.getMessage(), e);
		}

		throw new BadArgumentException("Unsupported ecc point type: " + type);
	}

	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#decodeEccPoint(AlgorithmIndicator, EccCurvePoint)
	 */
    @Override
    public Object decodeEccPoint(AlgorithmIndicator alg,
                                 EccCurvePoint eccPoint) throws InvalidKeySpecException, BadArgumentException {
        if(eccPoint instanceof EccP384CurvePoint){
            return decodeEccP384Point(alg,(EccP384CurvePoint) eccPoint);
        }
        return decodeEccP256Point(alg,(EccP256CurvePoint) eccPoint);
    }

	public Object decodeEccP256Point(AlgorithmIndicator alg,
			EccP256CurvePoint eccPoint) throws InvalidKeySpecException, BadArgumentException {
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
     * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#encodeEccPoint(AlgorithmIndicator, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP384CurvePoint.EccP384CurvePointChoices, PublicKey)
     */
    @Override
    public EccP384CurvePoint encodeEccPoint(AlgorithmIndicator alg,
                                            EccP384CurvePoint.EccP384CurvePointChoices type, PublicKey publicKey)
            throws BadArgumentException, InvalidKeySpecException {
        if(! (publicKey instanceof java.security.interfaces.ECPublicKey)){
            throw new BadArgumentException("Only ec public keys are supported, not " + publicKey.getClass().getSimpleName());
        }
        BCECPublicKey bcPub = toBCECPublicKey(alg, (java.security.interfaces.ECPublicKey) publicKey);

		try{
			if(type == EccP384CurvePoint.EccP384CurvePointChoices.uncompressed){
				return new EccP384CurvePoint(bcPub.getW().getAffineX(), bcPub.getW().getAffineY());
			}
			if(type == EccP384CurvePoint.EccP384CurvePointChoices.compressedy0 || type == EccP384CurvePoint.EccP384CurvePointChoices.compressedy1){

				return new EccP384CurvePoint(bcPub.getQ().getEncoded(true));
			}
			if(type == EccP384CurvePoint.EccP384CurvePointChoices.xonly){
				return new EccP384CurvePoint(bcPub.getW().getAffineX());
			}
		}catch(IOException e){
			throw new BadArgumentException("Invalid public key specified: " + e.getMessage(), e);
		}


		throw new BadArgumentException("Unsupported ecc point type: " + type);
    }

    public Object decodeEccP384Point(AlgorithmIndicator alg,
                                 EccP384CurvePoint eccPoint) throws InvalidKeySpecException, BadArgumentException {
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
                if(eccPoint.getType() == EccP384CurvePoint.EccP384CurvePointChoices.compressedy0){
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
	 * @see org.certificateservices.custom.c2x.common.crypto.CryptoManager#digest(byte[], AlgorithmIndicator)
	 */
	public byte[] digest(byte[] message, AlgorithmIndicator alg) throws BadArgumentException {
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
		throw new BadArgumentException("Unsupported hash algorithm: " + alg);
	}
		
	
	/**
	 * Help method to generate a certificate digest according to 1609.2 section 5.3.1 Signature algorithm.
	 * @param alg the algorithm to use.
	 * @param messageData the message data to digest
	 * @param signerCertificate the certificate used for signing, null if selfsigned data.
	 * @throws NoSuchAlgorithmException 
	 * @throws BadArgumentException
	 * @throws IOException 
	 */
	@Override
	public byte[] genIEEECertificateDigest(AlgorithmIndicator alg,byte[] messageData, org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signerCertificate) throws BadArgumentException, IOException{
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

	/**
	 * Method to encrypt a symmetric key according to IEEE 1609.2 2017 specification.
	 *
	 * @param keyType the algorithm specification of the recipients public key.
	 * @param encryptionKey the recipients public key to encrypt to.
	 * @param symmetricKey the symmetric key to encrypt (Should be AES 128)
	 * @param p1 the deviation used as recipient information (SHA256 Hash of certificate or "" if no related certificate is available).
	 * @return a EncryptedDataEncryptionKey with v,c,t set.
	 * @throws BadArgumentException if supplied parameters where invalid.
	 * @throws GeneralSecurityException if problems occurred performing the encryption.
	 */
	@Override
	public EncryptedDataEncryptionKey ieeeEceisEncryptSymmetricKey2017(EncryptedDataEncryptionKeyChoices keyType, PublicKey encryptionKey, SecretKey symmetricKey, byte[] p1) throws BadArgumentException, GeneralSecurityException{
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
	 * @throws BadArgumentException if supplied parameters where invalid.
	 * @throws GeneralSecurityException if problems occurred performing the encryption.
	 */
	public EncryptedDataEncryptionKey ieeeEceisEncryptSymmetricKey2017(EncryptedDataEncryptionKeyChoices keyType, PublicKey encryptionKey, SecretKey symmetricKey, byte[] p1, byte[] empericalPrivateKey) throws BadArgumentException, GeneralSecurityException{
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
		try {
			EccP256CurvePoint vPubPoint = new EccP256CurvePoint(V);
			EciesP256EncryptedKey key = new EciesP256EncryptedKey(vPubPoint, C, T);
			return new EncryptedDataEncryptionKey(keyType, key);
		}catch (IOException e){
			throw new BadArgumentException("Invalid ECC Curve Point: " + e.getMessage(),e);
		}

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
	 * @throws BadArgumentException if invalid arguments where specified.
	 * @throws InvalidKeySpecException if invalid key specification was given.
	 */
	@Override
	public SecretKey ieeeEceisDecryptSymmetricKey2017(EncryptedDataEncryptionKey encryptedDataEncryptionKey, PrivateKey decryptionKey, byte[] p1) throws InvalidKeyException, BadArgumentException, InvalidKeySpecException {
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
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#symmetricEncryptIEEE1609_2_2017(AlgorithmIndicator, byte[], byte[], byte[])
	 */
	@Override
	public byte[] symmetricEncryptIEEE1609_2_2017(AlgorithmIndicator alg, byte[] data, byte[] symmetricKey, byte[] nounce) throws BadArgumentException, GeneralSecurityException {
		if(alg.getAlgorithm().getSymmetric() == Symmetric.aes128Ccm) {
			CCMBlockCipher ccmBlockCipher = new CCMBlockCipher(new AESEngine());

			AEADParameters parameterSpec = new AEADParameters(new KeyParameter(symmetricKey), 128, nounce, null); //128 bit auth tag length
			ccmBlockCipher.init(true, parameterSpec);

			byte[] outData = new byte[ccmBlockCipher.getOutputSize(data.length)];
			int outputLen = ccmBlockCipher.processBytes(data, 0, data.length,
					outData, 0);
			try {
                ccmBlockCipher.doFinal(outData, outputLen);
            }catch (InvalidCipherTextException e){
			    throw new GeneralSecurityException("Invalid cipher text when performing symmetric encrypt: " + e.getMessage(),e);
            }

			return outData;
		}
		throw new BadArgumentException("Unsupported symmetric encryption algorithm specified: " + alg.getAlgorithm().getSymmetric());
	}

	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#symmetricDecryptIEEE1609_2_2017(AlgorithmIndicator, byte[], byte[], byte[])
	 */
	public byte[] symmetricDecryptIEEE1609_2_2017(AlgorithmIndicator alg, byte[] data, byte[] symmetricKey, byte[] nounce) throws BadArgumentException,  GeneralSecurityException {
		if(alg.getAlgorithm().getSymmetric() == Symmetric.aes128Ccm) {
			CCMBlockCipher ccmBlockCipher = new CCMBlockCipher(new AESEngine());

			AEADParameters parameterSpec = new AEADParameters(new KeyParameter(symmetricKey), 128, nounce, null); //128 bit auth tag length
			ccmBlockCipher.init(false, parameterSpec);

			byte[] outData = new byte[ccmBlockCipher.getOutputSize(data.length)];
			int outputLen = ccmBlockCipher.processBytes(data, 0, data.length,
					outData, 0);
			try{
			  ccmBlockCipher.doFinal(outData, outputLen);
            }catch (InvalidCipherTextException e){
                throw new GeneralSecurityException("Invalid cipher text when performing symmetric decrypt: " + e.getMessage(),e);
            }
			return outData;
		}
		throw new BadArgumentException("Unsupported symmetric encryption algorithm specified: " + alg.getAlgorithm().getSymmetric());
	}

	
	/**
	 * @see org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager#disconnect()
	 */
	@Override
	public void disconnect(){
	}
	/**
	 * Method to convert a EC public key to a BCECPublicKey
	 * @param alg specifying the related curve used.
	 * @param ecPublicKey key to convert
	 * @return a BCECPublicKey
	 * @throws BadArgumentException if one of the parameter contained invalid data.
	 * @throws InvalidKeySpecException if supplied key was invalid.
	 */
	@Override
	public BCECPublicKey toBCECPublicKey(AlgorithmIndicator alg, java.security.interfaces.ECPublicKey ecPublicKey) throws InvalidKeySpecException, BadArgumentException {
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
	public ECParameterSpec getECParameterSpec(AlgorithmIndicator alg) throws BadArgumentException{
		if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaNistP256){
			return ecNistP256Spec;
		}
		if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaBrainpoolP256r1){
			return brainpoolp256r1Spec;
		}
        if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaBrainpoolP384r1){
            return brainpoolp384r1Spec;
        }
		throw new BadArgumentException("Unsupported EC Algorithm: " + alg);
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
			throws IOException, BadArgumentException, SignatureException {
		return ecqvHelper.certReceiption(cert, r, alg, (ECPrivateKey) Ku, (ECPublicKey) signerPublicKey, signerCertificate);
	}

	protected ECCurve getECCurve(AlgorithmIndicator alg) throws BadArgumentException{
		if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaNistP256){
			return ecNistP256Curve;
		}
		if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaBrainpoolP256r1){
			return brainpoolp256r1;
		}
        if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaBrainpoolP384r1){
            return brainpoolP384r1;
        }
		throw new BadArgumentException("Unsupported EC Algorithm: " + alg);
	}

	protected ECPublicKey getECPublicKeyFromECPoint(AlgorithmIndicator alg, ECPoint eCPoint) throws InvalidKeySpecException, BadArgumentException {
		ECPublicKeySpec spec = new ECPublicKeySpec(eCPoint, getECParameterSpec(alg));
		return (ECPublicKey) keyFact.generatePublic(spec);
	}

	protected SignatureChoices getSignatureChoice(
			org.certificateservices.custom.c2x.common.crypto.Algorithm.Signature sigAlg) {
		switch (sigAlg) {
		case ecdsaNistP256:
			return SignatureChoices.ecdsaNistP256Signature;
		case ecdsaBrainpoolP256r1:
            return SignatureChoices.ecdsaBrainpoolP256r1Signature;
            case ecdsaBrainpoolP384r1:
		default:
			return SignatureChoices.ecdsaBrainpoolP384r1Signature;
		}
	}

	protected AlgorithmIndicator  getSignatureAlgorithm(SignatureChoices sigChoice) {
		switch (sigChoice) {
		case ecdsaNistP256Signature:
			return PublicVerificationKeyChoices.ecdsaNistP256;
		case ecdsaBrainpoolP256r1Signature:
            return PublicVerificationKeyChoices.ecdsaBrainpoolP256r1;
            case ecdsaBrainpoolP384r1Signature:
		default:
			return PublicVerificationKeyChoices.ecdsaBrainpoolP384r1;
		}
	}

	protected boolean verifyExplicitCertSignature(
			byte[] message,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature signature,
			org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate signCert,
			PublicKey publicKey) throws BadArgumentException,
			SignatureException, IOException {
		 
		AlgorithmIndicator alg = getSignatureAlgorithm(signature.getType());
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new BadArgumentException("Error no signature algorithm specified");
		}
		try{
			return verifySignatureDigest(genIEEECertificateDigest(alg,message, signCert), signature, publicKey);
		}catch(Exception e){
			if(e instanceof BadArgumentException){
				throw (BadArgumentException) e;
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
			PublicKey signerPublicKey) throws BadArgumentException,
			SignatureException, IOException {
		 
		AlgorithmIndicator alg = getSignatureAlgorithm(signature.getType());
		Algorithm.Signature sigAlg = alg.getAlgorithm().getSignature();
		if(sigAlg == null){
			throw new BadArgumentException("Error no signature algorithm specified");
		}
		try{
			return verifySignatureDigest(genIEEECertificateDigest(alg,message, signCert), signature, signerPublicKey);
		}catch(Exception e){
			if(e instanceof BadArgumentException){
				throw (BadArgumentException) e;
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

}
