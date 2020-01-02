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
package org.certificateservices.custom.c2x.etsits103097.v131.generator;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.*;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.BaseCertGenerator;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * Certificate Generator class for generating authorization ticket certificates for ETSI TS 103 097 v 1.3.1 standard.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ETSIAuthorizationTicketGenerator extends BaseCertGenerator {


	/**
	 * Main constructor using compressed keys.
	 * @param cryptoManager the crypto manager to use.
	 */
	public ETSIAuthorizationTicketGenerator(Ieee1609Dot2CryptoManager cryptoManager) throws SignatureException{
		super(cryptoManager, false);
	}

	/**
	 * Main constructor
	 * @param cryptoManager the crypto manager to use.
	 * @param useUncompressed if uncompressed keys should be used.
	 */
	public ETSIAuthorizationTicketGenerator(Ieee1609Dot2CryptoManager cryptoManager, boolean useUncompressed) throws SignatureException {
		super(cryptoManager, useUncompressed);
	}


	/**
	 * Method to generate an authorization ticket end entity certificate.
	 *
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Required
	 * @param subjectAssurance the subjectAssurance, Optional.
	 * @param appPermissions an array of app permissions set in certificate.
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
	public EtsiTs103097Certificate genAuthorizationTicket(
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			SubjectAssurance subjectAssurance,
			PsidSsp[] appPermissions,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey,
			Certificate signerCertificate,
			PublicKey signCertificatePublicKey,
			PrivateKey signCertificatePrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{


		PublicEncryptionKey encryptionKey = null;
		if(symmAlgorithm != null && encPublicKeyAlgorithm != null && encPublicKey != null){
			encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
		}
		PublicVerificationKey verifyKeyIndicator = new PublicVerificationKey(getPublicVerificationAlgorithm(signingPublicKeyAlgorithm), convertToPoint(signingPublicKeyAlgorithm, signPublicKey));


		return genAuthorizationTicket(validityPeriod, region, subjectAssurance, appPermissions,
				signingPublicKeyAlgorithm, verifyKeyIndicator, signerCertificate, signCertificatePublicKey, signCertificatePrivateKey,
				encryptionKey);

	}

	/**
	 * Method to generate an authorization ticket end entity certificate.
	 *
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Required
	 * @param subjectAssurance the subjectAssurance, Optional.
	 * @param appPermissions an array of app permissions set in certificate.
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required if type is explicit
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signerCertificate the signing certificate (Root CA), Required
	 * @param signCertificatePublicKey the signing certificates public key, Required
	 * @param signCertificatePrivateKey the signing certificates private key, Required
	 * @param encryptionKey The PublicEncryptionKey to include in the certificate.
	 * @return a new self signed certificate with root CA profile.
	 *
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public EtsiTs103097Certificate genAuthorizationTicket(
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			SubjectAssurance subjectAssurance,
			PsidSsp[] appPermissions,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicVerificationKey signPublicKey,
			Certificate signerCertificate,
			PublicKey signCertificatePublicKey,
			PrivateKey signCertificatePrivateKey,
			PublicEncryptionKey encryptionKey) throws IllegalArgumentException,  SignatureException, IOException{
		// See 6.4.8 ToBeSignedCertificate - certIssuePermissions for details
		CertificateId id = new CertificateId();

		SequenceOfPsidSsp appPermissionsSequence = null;
		if(appPermissions != null){
			appPermissionsSequence = new SequenceOfPsidSsp(appPermissions);
		}

		VerificationKeyIndicator vki = new VerificationKeyIndicator(signPublicKey);

		ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, new HashedId3(Hex.decode("000000")), new CrlSeries(0), validityPeriod, region, subjectAssurance, appPermissionsSequence, null, null, false, encryptionKey, vki);
		// In future when supporting implicit certificate cannot public key be null in following call.
		return (EtsiTs103097Certificate) genCert(tbs, CertificateType.explicit, signingPublicKeyAlgorithm,  null, signCertificatePrivateKey, signCertificatePublicKey,signerCertificate);

	}

	@Override
	protected Certificate newCertificate(IssuerIdentifier issuerIdentifier, ToBeSignedCertificate tbs,Signature signature){
		return new EtsiTs103097Certificate(issuerIdentifier,tbs,signature);
	}

	

}
