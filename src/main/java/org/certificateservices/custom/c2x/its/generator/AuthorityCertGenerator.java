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
package org.certificateservices.custom.c2x.its.generator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.List;

import org.certificateservices.custom.c2x.its.crypto.ITSCryptoManager;
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType;

/**
 * Certificate Generator class for generating certificates of types: RootCA, Authorization Authority and Enrollment Authority.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class AuthorityCertGenerator extends BaseCertGenerator {

	/**
	 * Main constructor
	 * @param cryptoManager the crypto manager to use.
	 */
	public AuthorityCertGenerator(ITSCryptoManager cryptoManager) {
		super(cryptoManager);
	}
	
	/**
	 * Constructor where it is possible to specify the certificate version to use.
	 * 
	 * @param certificateVersion the version to generate certificates for see Certificate.CERTIFICATE_VERSION_ constants.
	 * @param cryptoManager the crypto manager to use.
	 */
	public AuthorityCertGenerator(int certificateVersion, ITSCryptoManager cryptoManager) {
		super(certificateVersion, cryptoManager);
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
			byte[] subjectName, 
			List<BigInteger> itsAidList,
			int assuranceLevel,
			int confidenceLevel,
			Date validFrom, 
			Date validTo, 
			GeographicRegion geographicRegion,
			PublicKeyAlgorithm signingPublicKeyAlgorithm,
			PublicKey signPublicKey, 
			PrivateKey signPrivateKey,
			PublicKeyAlgorithm encPublicKeyAlgorithm,
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		return genCA(SubjectType.root_ca, subjectName, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, signPrivateKey, null);

	}
	
	/**
	 * Method to generate an Authorization Authority signed by a Root CA certificate 
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
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @param rootCAPrivateKey the private key of the root CA, Required
	 * @param rootCACertificate the certificate of the root CA, Required
	 * @return a new authorization authority certificate.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public Certificate genAuthorizationAuthorityCA(
			byte[] subjectName, 
			List<BigInteger> itsAidList,
			int assuranceLevel,
			int confidenceLevel,
			Date validFrom, 
			Date validTo, 
			GeographicRegion geographicRegion,
			PublicKeyAlgorithm signingPublicKeyAlgorithm,
			PublicKey signPublicKey, 
			PublicKeyAlgorithm encPublicKeyAlgorithm,
			PublicKey encPublicKey,
			PrivateKey rootCAPrivateKey,
			Certificate rootCACertificate) throws IllegalArgumentException,  SignatureException, IOException{

		return genCA(SubjectType.authorization_authority, subjectName, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, rootCAPrivateKey, rootCACertificate);

	}
	
	/**
	 * Method to generate an Enrollment Authority signed by a Root CA certificate 
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
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @param rootCAPrivateKey the private key of the root CA, Required
	 * @param rootCACertificate the certificate of the root CA, Required
	 * @return a new enrollment authority certificate.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public Certificate genEnrollmentAuthorityCA(
			byte[] subjectName, 
			List<BigInteger> itsAidList,
			int assuranceLevel,
			int confidenceLevel,
			Date validFrom, 
			Date validTo, 
			GeographicRegion geographicRegion,
			PublicKeyAlgorithm signingPublicKeyAlgorithm,
			PublicKey signPublicKey, 
			PublicKeyAlgorithm encPublicKeyAlgorithm,
			PublicKey encPublicKey,
			PrivateKey rootCAPrivateKey,
			Certificate rootCACertificate) throws IllegalArgumentException,  SignatureException, IOException{

		return genCA(SubjectType.enrollment_authority, subjectName, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, rootCAPrivateKey, rootCACertificate);

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
	 * @param encPublicKeyAlgorithm algorithm used for encryption, null if no encryption key should be included.
	 * @param encPublicKey public key used for encryption, null if no encryption key should be included.
	 * @param caPrivateKey private key of CA signing this certificate, for self signed it's own private key, Required
	 * @param caCertificate Certificate of CA signing this certificate, null indicates a self signed CA.
	 * @return a new CA certificate.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	protected Certificate genCA(
			SubjectType subjectType,
			byte[] subjectName, 
			List<BigInteger> itsAidList,
			int assuranceLevel,
			int confidenceLevel,
			Date validFrom, 
			Date validTo, 
			GeographicRegion geographicRegion,
			PublicKeyAlgorithm signingPublicKeyAlgorithm,
			PublicKey signPublicKey, 
			PublicKeyAlgorithm encPublicKeyAlgorithm,
			PublicKey encPublicKey,
			PrivateKey caPrivateKey,
			Certificate caCertificate) throws IllegalArgumentException,  SignatureException, IOException{
		
		SignerInfo signerInfo;
		if(subjectType != SubjectType.root_ca){
			if(certificateVersion == Certificate.CERTIFICATE_VERSION_1){
			  signerInfo = new SignerInfo(caCertificate);
			}else{
				try {
					signerInfo = new SignerInfo(new HashedId8(caCertificate, cryptoManager));
				} catch (NoSuchAlgorithmException e) {
					throw new SignatureException("Error no such algorithm exception: " + e.getMessage());
				} catch (InvalidKeySpecException e) {
					throw new SignatureException("Error invalid key exception: " + e.getMessage());
				}
			}
		}else{
			signerInfo = new SignerInfo(); // Self signed
		}


		return genCert(signerInfo, subjectType, subjectName, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, caPrivateKey, caCertificate);
	}
}
