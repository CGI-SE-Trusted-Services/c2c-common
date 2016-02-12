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
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.ToBeSignedCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator;


/**
 * Certificate Generator class for Authorization Cert, used by a Short Term (App) CA, using end entity certificate with cerificateRequest permissions.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class AuthorizationCertGenerator extends BaseCertGenerator {

	/**
	 * Main constructor using compressed keys.
	 * @param cryptoManager the crypto manager to use.
	 */
	public AuthorizationCertGenerator(Ieee1609Dot2CryptoManager cryptoManager) throws SignatureException{
		super(cryptoManager, false);
	}
	
	/**
	 * Main constructor
	 * @param cryptoManager the crypto manager to use.
	 * @param useUncompressed if uncompressed keys should be used.
	 */
	public AuthorizationCertGenerator(Ieee1609Dot2CryptoManager cryptoManager, boolean useUncompressed) throws SignatureException {
		super(cryptoManager, useUncompressed);
	}


	
	/**
	 * Method to generate a enrollment type end entity certificate.
	 * 
	 * @param type indicates if this is a implicit or explicit certificate, Required
	 * @param id the id if the certificate, see CertificateId for details, Required
	 * @param validityPeriod, the validity period of this certificate, Required
	 * @param region, the geographic region of the certificate, Required
	 * @param appPermission a list of app permissions.
	 * @param assuranceLevel the assurance level to use, 0-7, Required
	 * @param confidenceLevel the confidence level to use, 0-3, Required
	 * @param minChainDepth the minimal chain length of this PKI hierarchy, Required
	 * @param chainDepthRange the chain depth range, see 6.4.30 PsidGroupPermissions for details, Required
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required if type is explicit
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signerCertificate the signing certificate (Root CA), Required
	 * @param signCertificatePublicKey the signing certificates public key, Required
	 * @param signCertificatePrivateKey the signing certificates private key, Required
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @return a new self signed certificate with root CA profile.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public Certificate genAuthorizationCert(
			CertificateType type,
			CertificateId id, 
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			PsidSsp[] appPermissions,
			byte[] cracaid,
			int crlSeries,
			int assuranceLevel,
			int confidenceLevel,
			PublicVerificationKeyChoices signingPublicKeyAlgorithm,
			PublicKey signPublicKey, 
			Certificate signerCertificate,
			PublicKey signCertificatePublicKey,
			PrivateKey signCertificatePrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{
		
		if(appPermissions == null){
			throw new IllegalArgumentException("Error appPermissions cannot be null");
		}
		SequenceOfPsidSsp appPerms = new SequenceOfPsidSsp(appPermissions);
		
		
		PublicEncryptionKey encryptionKey = null;
		if(symmAlgorithm != null && encPublicKeyAlgorithm != null && encPublicKey != null){
			encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
		}
		SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);
		VerificationKeyIndicator vki;
		if(type == CertificateType.explicit){
			PublicVerificationKey verifyKeyIndicator = new PublicVerificationKey(signingPublicKeyAlgorithm, convertToPoint(signingPublicKeyAlgorithm, signPublicKey));
		    vki = new VerificationKeyIndicator(verifyKeyIndicator);
		}else{
			EccP256CurvePoint rv = new EccP256CurvePoint(new BigInteger("0")); // This is just a placeholder. Real rv is set by ECQVHelper.
		    vki = new VerificationKeyIndicator(rv);
		}
		ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, new HashedId3(cracaid), new CrlSeries(crlSeries), validityPeriod, region, subjectAssurance, appPerms, null, null, false, encryptionKey, vki);
		return genCert(tbs, type, signingPublicKeyAlgorithm, signPublicKey, signCertificatePrivateKey, signCertificatePublicKey,signerCertificate);

	}
	

}
