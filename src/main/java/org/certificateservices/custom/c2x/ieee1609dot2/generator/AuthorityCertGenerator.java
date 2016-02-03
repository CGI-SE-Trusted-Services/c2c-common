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
import java.util.Date;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.CrlSeries;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.ToBeSignedCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;


/**
 * Certificate Generator class for generating certificates of types: RootCA, Psedonum CA and Long Term CA.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class AuthorityCertGenerator extends BaseCertGenerator {

	/**
	 * Main constructor using compressed keys.
	 * @param cryptoManager the crypto manager to use.
	 */
	public AuthorityCertGenerator(Ieee1609Dot2CryptoManager cryptoManager) {
		super(cryptoManager, false);
	}
	
	/**
	 * Main constructor
	 * @param cryptoManager the crypto manager to use.
	 * @param useUncompressed if uncompressed keys should be used.
	 */
	public AuthorityCertGenerator(Ieee1609Dot2CryptoManager cryptoManager, boolean useUncompressed) {
		super(cryptoManager, useUncompressed);
	}

	/**
	 * Method to generate a self signed root CA.
	 * 
	 * @param subjectName the subject name to use in the certificate, null for empty name. Max 32 bytes.
	 * @param itsAidList list of ITS AID values, Required
	 * @param assuranceLevel the assurance level to use, 0-7, Required
	 * @param confidenceLevel the confidence level to use, 0-3, Required
	 * @param validFrom the valid from date in certificate, Required
	 * @param validTo the valid to date in certificate, Required
	 * @param geographicRegion the region the certificate should be valid, null for no geographic region.
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

			PublicVerificationKeyChoices signingPublicKeyAlgorithm,
			PublicKey signPublicKey, 
			PrivateKey signPrivateKey,
			SymmAlgorithm symmAlgorithm,
			BasePublicEncryptionKeyChoices encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		
		// TODO create signKey
//		PublicVerificationKey verifyKeyIndicator = new PublicVerificationKey(signingPublicKeyAlgorithm, convertToPoint(signingPublicKeyAlgorithm, signPublicKey));
//		PublicEncryptionKey encryptionKey = null;
//		if(symmAlgorithm != null && encPublicKeyAlgorithm != null && encPublicKey != null){
//			encryptionKey = new PublicEncryptionKey(symmAlgorithm, new BasePublicEncryptionKey(encPublicKeyAlgorithm, convertToPoint(encPublicKeyAlgorithm, encPublicKey)));
//		}
		// TODO
//		ToBeSignedCertificate tbs = new ToBeSignedCertificate(id, new HashedId3(Hex.decode("000000")), new CrlSeries(0), validityPeriod, region, assuranceLevel, appPermissions, certIssuePermissions, certRequestPermissions, false, encryptionKey, verifyKeyIndicator)
////		
////		return genCA(SubjectType.root_ca, subjectName, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, signPrivateKey, null);
return null;
	}
	
//	/**
//	 * Method to generate an Authorization Authority signed by a Root CA certificate 
//	 * 
//	 * @param subjectName the subject name to use in the certificate, null for empty name. Max 32 bytes.
//	 * @param itsAidList list of ITS AID values, Required
//	 * @param assuranceLevel the assurance level to use, 0-7, Required
//	 * @param confidenceLevel the confidence level to use, 0-3, Required
//	 * @param validFrom the valid from date in certificate, Required
//	 * @param validTo the valid to date in certificate, Required
//	 * @param geographicRegion the region the certificate should be valid, null for no geographic region.
//	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
//	 * @param signPublicKey public key used for verification of this certificate, Required
//	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
//	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
//	 * @param rootCAPrivateKey the private key of the root CA, Required
//	 * @param rootCACertificate the certificate of the root CA, Required
//	 * @return a new authorization authority certificate.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was illegal.
//	 * @throws SignatureException if internal signature problems occurred.
//	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
//	 */
//	public Certificate genAuthorizationAuthorityCA(
//			byte[] subjectName, 
//			List<BigInteger> itsAidList,
//			int assuranceLevel,
//			int confidenceLevel,
//			Date validFrom, 
//			Date validTo, 
//			GeographicRegion geographicRegion,
//			PublicKeyAlgorithm signingPublicKeyAlgorithm,
//			PublicKey signPublicKey, 
//			PublicKeyAlgorithm encPublicKeyAlgorithm,
//			PublicKey encPublicKey,
//			PrivateKey rootCAPrivateKey,
//			Certificate rootCACertificate) throws IllegalArgumentException,  SignatureException, IOException{
//
//		return genCA(SubjectType.authorization_authority, subjectName, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, rootCAPrivateKey, rootCACertificate);
//
//	}
	
//	/**
//	 * Method to generate an Enrollment Authority signed by a Root CA certificate 
//	 * 
//	 * @param subjectName the subject name to use in the certificate, null for empty name. Max 32 bytes.
//	 * @param itsAidList list of ITS AID values, Required
//	 * @param assuranceLevel the assurance level to use, 0-7, Required
//	 * @param confidenceLevel the confidence level to use, 0-3, Required
//	 * @param validFrom the valid from date in certificate, Required
//	 * @param validTo the valid to date in certificate, Required
//	 * @param geographicRegion the region the certificate should be valid, null for no geographic region.
//	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
//	 * @param signPublicKey public key used for verification of this certificate, Required
//	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
//	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
//	 * @param rootCAPrivateKey the private key of the root CA, Required
//	 * @param rootCACertificate the certificate of the root CA, Required
//	 * @return a new enrollment authority certificate.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was illegal.
//	 * @throws SignatureException if internal signature problems occurred.
//	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
//	 */
//	public Certificate genEnrollmentAuthorityCA(
//			byte[] subjectName, 
//			List<BigInteger> itsAidList,
//			int assuranceLevel,
//			int confidenceLevel,
//			Date validFrom, 
//			Date validTo, 
//			GeographicRegion geographicRegion,
//			PublicKeyAlgorithm signingPublicKeyAlgorithm,
//			PublicKey signPublicKey, 
//			PublicKeyAlgorithm encPublicKeyAlgorithm,
//			PublicKey encPublicKey,
//			PrivateKey rootCAPrivateKey,
//			Certificate rootCACertificate) throws IllegalArgumentException,  SignatureException, IOException{
//
//		return genCA(SubjectType.enrollment_authority, subjectName, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, rootCAPrivateKey, rootCACertificate);
//
//	}
//
//	/**
//	 * Method to generate a self signed root CA.
//	 * 
//	 * @param subjectName the subject name to use in the certificate, null for empty name. Max 32 bytes.
//	 * @param itsAidList list of ITS AID values, Required
//	 * @param assuranceLevel the assurance level to use, 0-7, Required
//	 * @param confidenceLevel the confidence level to use, 0-3, Required
//	 * @param validFrom the valid from date in certificate, Required
//	 * @param validTo the valid to date in certificate, Required
//	 * @param geographicRegion the region the certificate should be valid, null for no geographic region.
//	 * @param signingPublicKeyAlgorithm algorithm used for signing and verification, Required
//	 * @param signPublicKey public key used for verification of this certificate, Required
//	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
//	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
//	 * @param caPrivateKey private key of CA signing this certificate, for self signed it's own private key, Required
//	 * @param caCertificate Certificate of CA signing this certificate, null indicates a self signed CA.
//	 * @return a new CA certificate.
//	 * 
//	 * @throws IllegalArgumentException if supplied arguments was illegal.
//	 * @throws SignatureException if internal signature problems occurred.
//	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
//	 */
//	protected Certificate genCA(
//			SubjectType subjectType,
//			byte[] subjectName, 
//			List<BigInteger> itsAidList,
//			int assuranceLevel,
//			int confidenceLevel,
//			Date validFrom, 
//			Date validTo, 
//			GeographicRegion geographicRegion,
//			PublicKeyAlgorithm signingPublicKeyAlgorithm,
//			PublicKey signPublicKey, 
//			PublicKeyAlgorithm encPublicKeyAlgorithm,
//			PublicKey encPublicKey,
//			PrivateKey caPrivateKey,
//			Certificate caCertificate) throws IllegalArgumentException,  SignatureException, IOException{
//		
//		SignerInfo signerInfo;
//		if(subjectType != SubjectType.root_ca){
//			signerInfo = new SignerInfo(caCertificate);	
//		}else{
//			signerInfo = new SignerInfo(); // Self signed
//		}
//
//
//		return genCert(signerInfo, subjectType, subjectName, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, caPrivateKey, caCertificate);
//	}
}
