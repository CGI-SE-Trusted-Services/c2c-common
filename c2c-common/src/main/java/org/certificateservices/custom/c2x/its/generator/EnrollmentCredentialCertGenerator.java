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
import java.util.Date;
import java.util.List;

import org.certificateservices.custom.c2x.its.crypto.CryptoManager;
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType;

/**
 * Certificate Generator class for generating a enrollment CAs enrollment certificates.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EnrollmentCredentialCertGenerator extends BaseCertGenerator {

	
	private Certificate enrollmentCA;
	private PrivateKey enrollmentCAPrivateKey;
	
	/**
	 * Main creating a instance of a enrollment credential certificate generator for one enrollment authority.
	 * 
	 * @param cryptoManager the crypto manager to use.
	 * @param enrollmentCA the CA certificate of the enrollment CA to use.
	 * @param enrollmentCAPrivateKey the private key of the enrollment CA.
	 * 
	 */
	public EnrollmentCredentialCertGenerator(CryptoManager cryptoManager, Certificate enrollmentCA, PrivateKey enrollmentCAPrivateKey) {
		super(cryptoManager);
		this.enrollmentCA = enrollmentCA;
		this.enrollmentCAPrivateKey = enrollmentCAPrivateKey;
	}


	
	/**
	 * Method to generate an Enrollment Credential using one of the signer infos certificate_digest_with_ecdsap256 or certificate
	 * 
	 * @param signerInfoType one of certificate_digest_with_ecdsap256 or certificate
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
	 * @return a new enrollment credential.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public Certificate genEnrollmentCredential(
			SignerInfoType signerInfoType,
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
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

		if(signerInfoType == SignerInfoType.certificate || signerInfoType == SignerInfoType.certificate_digest_with_ecdsap256){
			SignerInfo signerInfo = null;
			if(signerInfoType == SignerInfoType.certificate){
				signerInfo = new SignerInfo(enrollmentCA);
			}else{
				try {
					HashedId8 hash = new HashedId8(cryptoManager.digest(enrollmentCA.getEncoded(), PublicKeyAlgorithm.ecdsa_nistp256_with_sha256));
					signerInfo = new SignerInfo(hash);
				} catch (NoSuchAlgorithmException e) {
					throw new SignatureException("Error generating certificate, no such algorithm: " + e.getMessage(),e);
				}				
			}
		
			return genCert(signerInfo, SubjectType.enrollment_credential, subjectName, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, enrollmentCAPrivateKey, enrollmentCA);
		}
		throw new IllegalArgumentException("Unsupported signer info type: " + signerInfoType);

	}
	
	/**
	 * Method to generate an Enrollment Credential using signer info  certificate_chain
	 * 
	 * @param signerInfoCAChain the certificate chain to include in the signer info. The last element of the chain shall contain 
	 * the certificate used to sign the message, the next to last element shall contain the certificate of the CA that signed the 
	 * last certificate and so on. The first element of the chain needs not be a root certificate.
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
	 * @return a new enrollment credential.
	 * 
	 * @throws IllegalArgumentException if supplied arguments was illegal.
	 * @throws SignatureException if internal signature problems occurred.
	 * @throws IOException if communication problems with underlying systems occurred generating the certificate.
	 */
	public Certificate genEnrollmentCredential(
			List<Certificate> signerInfoCAChain,
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
			PublicKey encPublicKey) throws IllegalArgumentException,  SignatureException, IOException{

			SignerInfo signerInfo = new SignerInfo(signerInfoCAChain);					
			return genCert(signerInfo, SubjectType.enrollment_credential, subjectName, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, enrollmentCAPrivateKey, enrollmentCA);
	}



}
