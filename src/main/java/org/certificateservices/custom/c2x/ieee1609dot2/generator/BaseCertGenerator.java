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
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.ECQVHelper;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
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
	protected Certificate signAndGenCertificate(int version, IssuerIdentifier issuerId, ToBeSignedCertificate tbs,  PublicVerificationKeyChoices alg, PublicKey publicKey, PrivateKey privateKey, CertificateType certType, Certificate signCert) throws IOException, IllegalArgumentException, SignatureException{
		Signature signature = cryptoManager.signMessage(tbs.getEncoded(), alg, publicKey, privateKey, certType,signCert);
		
		return new Certificate(version, issuerId, tbs, signature);		
	}
	
	/**
	 * Help method to convert a public key to EccP256CurvePoint using given compression.
	 */
	EccP256CurvePoint convertToPoint(AlgorithmIndicator alg, PublicKey pk) throws IllegalArgumentException{
		try {
			return cryptoManager.encodeEccPoint(alg, (useUncompressed ? EccP256CurvePointChoices.uncompressed : EccP256CurvePointChoices.compressedy0), pk);
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException("Error, invalid keyspec: " + e.getMessage());
		}
	}
	
	protected Certificate genCert(ToBeSignedCertificate tbs, CertificateType certType, AlgorithmIndicator alg,  PublicKey publicKey, PrivateKey signingPrivateKey, PublicKey signingPublicKey, Certificate signingCert) throws IOException, IllegalArgumentException, SignatureException{
		byte[] toBeSignedData = tbs.getEncoded();
		IssuerIdentifier issuerIdentifier;
		try{
			if(signingCert == null){
				issuerIdentifier = new IssuerIdentifier(HashAlgorithm.sha256);
			}else{
				HashedId8 h8 = new HashedId8(cryptoManager.digest(signingCert.getEncoded(), HashAlgorithm.sha256));
				issuerIdentifier = new IssuerIdentifier(IssuerIdentifier.IssuerIdentifierChoices.sha256AndDigest,h8);
			}
			Signature signature;
			if(certType == CertificateType.explicit){
			  signature = cryptoManager.signMessage(toBeSignedData, alg, publicKey, signingPrivateKey, certType, signingCert);
			  return new Certificate(issuerIdentifier, tbs, signature);
			}else{
				ImplicitCertificateData cert = new ImplicitCertificateData(issuerIdentifier, tbs);
				return ecqvHelper.genImplicitCertificate(cert, alg, (ECPublicKey) publicKey, signingCert, (BCECPublicKey) signingPublicKey, (BCECPrivateKey) signingPrivateKey);

			}
			
		}catch(NoSuchAlgorithmException e){
			throw new IllegalArgumentException("Error, no such algorithm exception: " + e.getMessage());
		}
	}
	
	protected PublicVerificationKeyChoices getPublicVerificationAlgorithm(
			AlgorithmIndicator signingPublicKeyAlgorithm) {
		switch(signingPublicKeyAlgorithm.getAlgorithm().getSignature()){
		case ecdsaNistP256:
			return PublicVerificationKeyChoices.ecdsaNistP256;
		case ecdsaBrainpoolP256r1:
			return PublicVerificationKeyChoices.ecdsaBrainpoolP256r1;
		}
		throw new IllegalArgumentException("Error unsupported Public Verification Algorithm specified: " + signingPublicKeyAlgorithm.getAlgorithm().getSignature());
	}
		
}
