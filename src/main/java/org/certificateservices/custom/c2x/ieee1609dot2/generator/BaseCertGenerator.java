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
package org.certificateservices.custom.c2x.ieee1609dot2.generator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.common.crypto.ECQVHelper;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.ToBeSignedCertificate;


/**
 * Base CertGenerator class containing common methods.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

public abstract class BaseCertGenerator {
	
	protected static final int DEFAULT_CERT_VERSION = 1;
	
	Ieee1609Dot2CryptoManager cryptoManager = null;
	boolean useUncompressed = false;
	
	ECQVHelper ecqvHelper;	
	
	public BaseCertGenerator(Ieee1609Dot2CryptoManager cryptoManager, boolean useUncompressed) throws SignatureException{
		this.cryptoManager = cryptoManager;
		this.useUncompressed = useUncompressed;
		
		ecqvHelper = new ECQVHelper(cryptoManager);

	}
	
	/**
	 * Generate and attaches a signature to the given certificate.
	 */
	protected Certificate signAndGenCertificate(int version, IssuerIdentifier issuerId, ToBeSignedCertificate tbs,  PublicVerificationKeyChoices alg, PublicKey publicKey, PrivateKey privateKey, CertificateType certType, Certificate signCert) throws IOException, SignatureException, BadArgumentException {
		Signature signature = cryptoManager.signMessage(tbs.getEncoded(), alg, privateKey, certType,signCert);

		return new Certificate(version, issuerId, tbs, signature);		
	}
	
	/**
	 * Help method to convert a public key to EccP256CurvePoint using given compression.
	 */
	protected COERChoice convertToPoint(AlgorithmIndicator alg, PublicKey pk) throws IOException{
		return convertToPoint(alg, pk, cryptoManager, useUncompressed);
	}

	/**
	 * Common static help method used by several generators to convert a public key to a ECPoint
	 */
	public static COERChoice convertToPoint(AlgorithmIndicator alg, PublicKey pk, Ieee1609Dot2CryptoManager cryptoManager, boolean useUncompressed) throws IOException {
		try {
			if(alg.getAlgorithm().getSignature() == Algorithm.Signature.ecdsaBrainpoolP384r1){
				return cryptoManager.encodeEccPoint(alg, (useUncompressed ? EccP384CurvePoint.EccP384CurvePointChoices.uncompressed : EccP384CurvePoint.EccP384CurvePointChoices.compressedy0), pk);
			}
			return cryptoManager.encodeEccPoint(alg, (useUncompressed ? EccP256CurvePointChoices.uncompressed : EccP256CurvePointChoices.compressedy0), pk);
		} catch (InvalidKeySpecException e) {
			throw new IOException("Error, invalid keyspec: " + e.getMessage(), e);
		} catch (BadArgumentException e) {
			throw new IOException("Error, bad argument: " + e.getMessage(), e);
		}
	}
	
	public Certificate genCert(ToBeSignedCertificate tbs, CertificateType certType, AlgorithmIndicator alg,  PublicKey publicKey, PrivateKey signingPrivateKey, PublicKey signingPublicKey, Certificate signingCert) throws IOException, SignatureException{
		byte[] toBeSignedData = tbs.getEncoded();
		IssuerIdentifier issuerIdentifier;
		try{
			HashAlgorithm hashAlgorithm = alg.getAlgorithm().getHash() == Algorithm.Hash.sha256 ? HashAlgorithm.sha256 : HashAlgorithm.sha384;
			IssuerIdentifier.IssuerIdentifierChoices issuerIdentifierType = alg.getAlgorithm().getHash() == Algorithm.Hash.sha256 ? IssuerIdentifier.IssuerIdentifierChoices.sha256AndDigest : IssuerIdentifier.IssuerIdentifierChoices.sha384AndDigest;
			if(signingCert == null){
				issuerIdentifier = new IssuerIdentifier(hashAlgorithm);
			}else{
				HashedId8 h8 = new HashedId8(cryptoManager.digest(signingCert.getEncoded(), hashAlgorithm));
				issuerIdentifier = new IssuerIdentifier(issuerIdentifierType,h8);
			}
			Signature signature;
			if(certType == CertificateType.explicit){
			  signature = cryptoManager.signMessage(toBeSignedData, alg, signingPrivateKey, certType, signingCert);
			  return newCertificate(issuerIdentifier, tbs, signature);
			}else{
				ImplicitCertificateData cert = new ImplicitCertificateData(issuerIdentifier, tbs);
				return ecqvHelper.genImplicitCertificate(cert, alg, (ECPublicKey) publicKey, signingCert, (BCECPublicKey) signingPublicKey, (BCECPrivateKey) signingPrivateKey);

			}
			
		}catch(NoSuchAlgorithmException e){
			throw new IOException("Error, no such algorithm exception: " + e.getMessage(), e);
		}catch (BadArgumentException e){
			throw new IOException("Error, bad arguments : " + e.getMessage(), e);
		}
	}

	protected Certificate newCertificate(IssuerIdentifier issuerIdentifier, ToBeSignedCertificate tbs,Signature signature) throws IOException{
		return new Certificate(issuerIdentifier, tbs, signature);
	}
	
	public static PublicVerificationKeyChoices getPublicVerificationAlgorithm(
			AlgorithmIndicator signingPublicKeyAlgorithm) throws IOException{
		switch(signingPublicKeyAlgorithm.getAlgorithm().getSignature()){
		case ecdsaNistP256:
			return PublicVerificationKeyChoices.ecdsaNistP256;
		case ecdsaBrainpoolP256r1:
			return PublicVerificationKeyChoices.ecdsaBrainpoolP256r1;
		case ecdsaBrainpoolP384r1:
			return PublicVerificationKeyChoices.ecdsaBrainpoolP384r1;
		}
		throw new IOException("Error unsupported Public Verification Algorithm specified: " + signingPublicKeyAlgorithm.getAlgorithm().getSignature());
	}
		
}
