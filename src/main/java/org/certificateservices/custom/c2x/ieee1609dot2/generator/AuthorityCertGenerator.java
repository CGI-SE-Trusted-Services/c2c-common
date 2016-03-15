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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.ToBeSignedCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator;


/**
 * Certificate Generator class for generating certificates of types: RootCA, Short Term CA (App) and Long Term CA (Enroll).
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class AuthorityCertGenerator extends BaseCertGenerator {

	/**
	 * Main constructor using compressed keys.
	 * @param cryptoManager the crypto manager to use.
	 */
	public AuthorityCertGenerator(Ieee1609Dot2CryptoManager cryptoManager) throws SignatureException{
		super(cryptoManager, false);
	}
	
	/**
	 * Main constructor
	 * @param cryptoManager the crypto manager to use.
	 * @param useUncompressed if uncompressed keys should be used.
	 */
	public AuthorityCertGenerator(Ieee1609Dot2CryptoManager cryptoManager, boolean useUncompressed) throws SignatureException {
		super(cryptoManager, useUncompressed);
	}

	/**
	 * Method to generate a self signed root CA.
	 * 
	 * @param id the id if the certificate, see CertificateId for details, Required
	 * @param validityPeriod, the validity period of this certificate, Required
	 * @param region, the geographic region of the certificate, Required
	 * @param assuranceLevel the assurance level to use, 0-7, Required
	 * @param confidenceLevel the confidence level to use, 0-3, Required
	 * @param minChainDepth the minimal chain length of this PKI hierarchy, Required
	 * @param chainDepthRange the chain depth range, see 6.4.30 PsidGroupPermissions for details, Required
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
	 * @param signPublicKey public key used for verification of this certificate, Required
	 * @param signPrivateKey private key used to sign this certificate, Required
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
			int assuranceLevel,
			int confidenceLevel,
			int minChainDepth,
			int chainDepthRange,
			AlgorithmIndicator signingPublicKeyAlgorithm,
			PublicKey signPublicKey, 
			PrivateKey signPrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		// See 6.4.8 ToBeSignedCertificate - certIssuePermissions for details
		SubjectPermissions sp = new SubjectPermissions(SubjectPermissionsChoices.all, null);
		
		PsidGroupPermissions pgp =  new PsidGroupPermissions(sp, minChainDepth, chainDepthRange, new EndEntityType(true, true));
		SequenceOfPsidGroupPermissions certIssuePermissions = new SequenceOfPsidGroupPermissions(new PsidGroupPermissions[] {pgp});
		
		PublicVerificationKey verifyKeyIndicator = new PublicVerificationKey(getPublicVerificationAlgorithm(signingPublicKeyAlgorithm), convertToPoint(signingPublicKeyAlgorithm, signPublicKey));
		PublicEncryptionKey encryptionKey = null;
		if(symmAlgorithm != null && encPublicKeyAlgorithm != null && encPublicKey != null){
			encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
		}
		SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);
		
		VerificationKeyIndicator vki = new VerificationKeyIndicator(verifyKeyIndicator);
		ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, new HashedId3(Hex.decode("000000")), new CrlSeries(0), validityPeriod, region, subjectAssurance, null, certIssuePermissions, null, false, encryptionKey, vki);
		return genCert(tbs, CertificateType.explicit, signingPublicKeyAlgorithm, signPublicKey,signPrivateKey, signPublicKey,null);

	}
	
	/**
	 * Method to generate a Long term enrollment CA
	 * 
	 * @param type indicates if this is a implicit or explicit certificate, Required
	 * @param id the id if the certificate, see CertificateId for details, Required
	 * @param validityPeriod, the validity period of this certificate, Required
	 * @param region, the geographic region of the certificate, Required
	 * @param subjectPermissions a list of subject permissions, null of all.
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
	public Certificate genLongTermEnrollmentCA(
			CertificateType type,
			CertificateId id, 
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			PsidSspRange[] subjectPermissions,
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

		return genSubCA(type, id, validityPeriod, region, subjectPermissions, true, cracaid, crlSeries, assuranceLevel, confidenceLevel, minChainDepth, chainDepthRange, signingPublicKeyAlgorithm, signPublicKey, signerCertificate, signCertificatePublicKey,signCertificatePrivateKey, symmAlgorithm, encPublicKeyAlgorithm, encPublicKey);
	}
	
	/**
	 * Method to generate a short term authorization CA
	 * 
	 * @param type indicates if this is a implicit or explicit certificate, Required
	 * @param id the id if the certificate, see CertificateId for details, Required
	 * @param validityPeriod, the validity period of this certificate, Required
	 * @param region, the geographic region of the certificate, Required
	 * @param subjectPermissions a list of subject permissions, null of all.
	 * @param assuranceLevel the assurance level to use, 0-7, Required
	 * @param confidenceLevel the confidence level to use, 0-3, Required
	 * @param minChainDepth the minimal chain length of this PKI hierarchy, Required
	 * @param chainDepthRange the chain depth range, see 6.4.30 PsidGroupPermissions for details, Required
	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
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
	public Certificate genAuthorizationCA(
			CertificateType type,
			CertificateId id, 
			ValidityPeriod validityPeriod,
			GeographicRegion region,
			PsidSspRange[] subjectPermissions,
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

		return genSubCA(type, id, validityPeriod, region, subjectPermissions, false, cracaid, crlSeries, assuranceLevel, confidenceLevel, minChainDepth, chainDepthRange, signingPublicKeyAlgorithm, signPublicKey, signerCertificate, signPublicKey, signCertificatePrivateKey, symmAlgorithm, encPublicKeyAlgorithm, encPublicKey);
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
		SequenceOfPsidGroupPermissions certIssuePermissions = new SequenceOfPsidGroupPermissions(new PsidGroupPermissions[] {pgp});
		
		
		PublicEncryptionKey encryptionKey = null;
		if(symmAlgorithm != null && encPublicKeyAlgorithm != null && encPublicKey != null){
			encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
		}
		SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);
		VerificationKeyIndicator vki;
		if(type == CertificateType.explicit){
			PublicVerificationKey verifyKeyIndicator = new PublicVerificationKey(getPublicVerificationAlgorithm(signingPublicKeyAlgorithm), convertToPoint(signingPublicKeyAlgorithm, signPublicKey));
		  vki = new VerificationKeyIndicator(verifyKeyIndicator);
		}else{
			EccP256CurvePoint rv = new EccP256CurvePoint(new BigInteger("0")); // This is just a placeholder. Real rv is set by ECQVHelper.
		    vki = new VerificationKeyIndicator(rv);
		}
		ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, new HashedId3(cracaid), new CrlSeries(crlSeries), validityPeriod, region, subjectAssurance, null, certIssuePermissions, null, false, encryptionKey, vki);
		return genCert(tbs, type, signingPublicKeyAlgorithm, signPublicKey, signCertificatePrivateKey, signCertificatePublicKey,signerCertificate);

	}


	

}
