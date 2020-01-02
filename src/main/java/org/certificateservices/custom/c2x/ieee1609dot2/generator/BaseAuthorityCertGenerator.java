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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;


/**
 * Certificate Generator class for generating certificates of types: RootCA, Short Term CA (App) and Long Term CA (Enroll).
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public abstract class BaseAuthorityCertGenerator extends BaseCertGenerator {

	/**
	 * Main constructor using compressed keys.
	 * @param cryptoManager the crypto manager to use.
	 */
	public BaseAuthorityCertGenerator(Ieee1609Dot2CryptoManager cryptoManager) throws SignatureException{
		super(cryptoManager, false);
	}

	/**
	 * Main constructor
	 * @param cryptoManager the crypto manager to use.
	 * @param useUncompressed if uncompressed keys should be used.
	 */
	public BaseAuthorityCertGenerator(Ieee1609Dot2CryptoManager cryptoManager, boolean useUncompressed) throws SignatureException {
		super(cryptoManager, useUncompressed);
	}

	/**
	 * A more general Root CA generator constructor for custom Root CA certificate profile.
	 *
	 * @param id the id if the certificate, see CertificateId for details, Required
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Required
	 * @param subjectAssurance the subjectAssurance, Optional.
	 * @param appPermissions list of appPermissions, use null to not set any app permissions.
	 * @param certIssuePermissions list of certIssuePermissions, use null to not set any cert issue permissions.
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signPrivateKey private key used to sign this certificate, Required
	 * @param symmAlgorithm the type of symmetric algorithm used when signing.
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @return a new self signed certificate with root CA profile.
	 *
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public Certificate genRootCA(
			CertificateId id,
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			SubjectAssurance subjectAssurance,
			PsidSsp[] appPermissions,
			PsidGroupPermissions[] certIssuePermissions,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey,
			PrivateKey signPrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		// See 6.4.8 ToBeSignedCertificate - certIssuePermissions for details
		SequenceOfPsidSsp appPermissionsSequence = null;
		if(appPermissions != null){
			appPermissionsSequence = new SequenceOfPsidSsp(appPermissions);
		}
		SequenceOfPsidGroupPermissions certIssuePermissionsSequence = null;
		if(certIssuePermissions != null) {
			certIssuePermissionsSequence = new SequenceOfPsidGroupPermissions(certIssuePermissions);
		}

		PublicVerificationKey verifyKeyIndicator = new PublicVerificationKey(getPublicVerificationAlgorithm(signingPublicKeyAlgorithm), convertToPoint(signingPublicKeyAlgorithm, signPublicKey));
		PublicEncryptionKey encryptionKey = null;
		if(symmAlgorithm != null && encPublicKeyAlgorithm != null && encPublicKey != null){
			encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
		}

		VerificationKeyIndicator vki = new VerificationKeyIndicator(verifyKeyIndicator);
		ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, new HashedId3(Hex.decode("000000")), new CrlSeries(0), validityPeriod, region, subjectAssurance, appPermissionsSequence, certIssuePermissionsSequence, null, false, encryptionKey, vki);
		return genCert(tbs, CertificateType.explicit, signingPublicKeyAlgorithm, signPublicKey,signPrivateKey, signPublicKey,null);

	}


	/**
	 * Method to create a general sub CA either enrollment or authorization CA with custom specified
	 * appPermissions and certIssuePermissions.
	 *
	 * @param type indicates if this is a implicit or explicit certificate, Required
	 * @param id the id if the certificate, see CertificateId for details, Required
	 * @param validityPeriod the validity period of this certificate, Required
	 * @param region the geographic region of the certificate, Optional
	 * @param subjectAssurance the subjectAssurance, Optional.
	 * @param appPermissions list of appPermissions, use null to not set any app permissions.
	 * @param certIssuePermissions list of certIssuePermissions, use null to not set any cert issue permissions.
	 * @param cracaid cracaid valie to set in certificate, Required.
	 * @param crlSeries the crlSeries to set in certificate, Required.
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signerCertificate the signing certificate (Root CA), Required
	 * @param signCertificatePublicKey the signing certificates public key, Required
	 * @param signCertificatePrivateKey the signing certificates private key, Required
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @return a newly created sub ca certificate.
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public Certificate genSubCA(
			CertificateType type,
			CertificateId id,
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			SubjectAssurance subjectAssurance,
			List<PsidSsp> appPermissions,
			List<PsidGroupPermissions> certIssuePermissions,
			byte[] cracaid,
			int crlSeries,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey,
			Certificate signerCertificate,
			PublicKey signCertificatePublicKey,
			PrivateKey signCertificatePrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		SequenceOfPsidSsp appPermissionsSequence = null;
		if(appPermissions != null){
			appPermissionsSequence = new SequenceOfPsidSsp(appPermissions);
		}
		// See 6.4.8 ToBeSignedCertificate - certIssuePermissions for details
		SequenceOfPsidGroupPermissions certIssuePermissionsSequence = null;
		if(certIssuePermissions != null){
			certIssuePermissionsSequence = new SequenceOfPsidGroupPermissions(certIssuePermissions);
		}

		PublicEncryptionKey encryptionKey = null;
		if(symmAlgorithm != null && encPublicKeyAlgorithm != null && encPublicKey != null){
			encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
		}
		VerificationKeyIndicator vki;
		if(type == CertificateType.explicit){
			PublicVerificationKey verifyKeyIndicator = new PublicVerificationKey(getPublicVerificationAlgorithm(signingPublicKeyAlgorithm), convertToPoint(signingPublicKeyAlgorithm, signPublicKey));
			vki = new VerificationKeyIndicator(verifyKeyIndicator);
		}else{
			EccP256CurvePoint rv = new EccP256CurvePoint(new BigInteger("0")); // This is just a placeholder. Real rv is set by ECQVHelper.
			vki = new VerificationKeyIndicator(rv);
		}
		ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, new HashedId3(cracaid), new CrlSeries(crlSeries), validityPeriod, region, subjectAssurance, appPermissionsSequence, certIssuePermissionsSequence, null, false, encryptionKey, vki);
		return genCert(tbs, type, signingPublicKeyAlgorithm, signPublicKey, signCertificatePrivateKey, signCertificatePublicKey,signerCertificate);

	}

	protected Certificate genSubCA(
			CertificateType type,
			CertificateId id, 
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			PsidSspRange[] subjectPermissions,
			boolean enrollmentCA,
			byte[] cracaid,
			int crlSeries,
			int assuranceLevel,
			int confidenceLevel,
			int minChainDepth,
			int chainDepthRange,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey, 
			Certificate signerCertificate,
			PublicKey signCertificatePublicKey,
			PrivateKey signCertificatePrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		// See 6.4.8 ToBeSignedCertificate - certIssuePermissions for details
		SubjectPermissions sp;
		if(subjectPermissions == null){
			sp = new SubjectPermissions(SubjectPermissionsChoices.all, null);
		}else{
			sp = new SubjectPermissions(SubjectPermissionsChoices.explicit, new SequenceOfPsidSspRange(subjectPermissions));
		}
		
		PsidGroupPermissions pgp;
		if(enrollmentCA){
		  pgp =  new PsidGroupPermissions(sp, minChainDepth, chainDepthRange, new EndEntityType(false, true));
		}else{
		  pgp =  new PsidGroupPermissions(sp, minChainDepth, chainDepthRange, new EndEntityType(true, false));
		}
		ArrayList<PsidGroupPermissions> certIssuePermissions = new ArrayList<PsidGroupPermissions>();
		certIssuePermissions.add(pgp);

		SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);
		return genSubCA(type,id,validityPeriod,region,subjectAssurance,null,certIssuePermissions,cracaid,crlSeries,signingPublicKeyAlgorithm,signPublicKey,signerCertificate,signCertificatePublicKey,signCertificatePrivateKey,symmAlgorithm,encPublicKeyAlgorithm,encPublicKey);
	}




	

}
