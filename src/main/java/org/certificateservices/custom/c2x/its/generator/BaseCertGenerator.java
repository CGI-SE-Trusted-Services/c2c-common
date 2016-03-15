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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.its.crypto.ITSCryptoManager;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAssurance;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttribute;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectInfo;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType;
import org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestriction;


/**
 * Base CertGenerator class containing common methods.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

public abstract class BaseCertGenerator {
	
	protected static final int DEFAULT_CERT_VERSION = 1;
	
	ITSCryptoManager cryptoManager = null;
	
	public BaseCertGenerator(ITSCryptoManager cryptoManager){
		this.cryptoManager = cryptoManager;
	}
	
	/**
	 * Generate and attaches a signature to the given certificate.
	 */
	protected Certificate signCertificate(Certificate cert, PublicKeyAlgorithm pubAlg, PrivateKey privateKey) throws IOException, IllegalArgumentException, SignatureException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream out = new DataOutputStream(baos);
		cert.encode(out);
		cert.attachSignature(cryptoManager.signMessage(baos.toByteArray(), pubAlg, privateKey));
		return cert;		
	}
	
	/**
	 * Method to generate a certificate
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
	protected Certificate genCert(
			SignerInfo signerInfo,
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

		
		if(subjectType != SubjectType.root_ca && caCertificate == null){
			throw new IllegalArgumentException("Wrong no signing CA certificate was given.");
		}
		
		List<SignerInfo> signerInfos = new ArrayList<SignerInfo>();		
		signerInfos.add(signerInfo); // Self signed
		

		SubjectInfo subjectInfo = new SubjectInfo(subjectType, subjectName);

		List<SubjectAttribute> subjectAttributes =  new ArrayList<SubjectAttribute>();
		try{			
			org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey spk = new org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey(
					signingPublicKeyAlgorithm, cryptoManager.encodeEccPoint(signingPublicKeyAlgorithm, EccPointType.compressed_lsb_y_0, signPublicKey));
			subjectAttributes.add(new SubjectAttribute(SubjectAttributeType.verification_key, spk));
			if(encPublicKey != null){
				org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey epk = new org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey(
						encPublicKeyAlgorithm, cryptoManager.encodeEccPoint(encPublicKeyAlgorithm, EccPointType.compressed_lsb_y_0, encPublicKey), encPublicKeyAlgorithm.getRelatedSymmetricAlgorithm());
				subjectAttributes.add(new SubjectAttribute(SubjectAttributeType.encryption_key, epk));
			}
			subjectAttributes.add(new SubjectAttribute(new SubjectAssurance(assuranceLevel, confidenceLevel)));
		
			if(itsAidList != null){
			  subjectAttributes.add(new SubjectAttribute(SubjectAttributeType.its_aid_list, getIntXList(itsAidList)));
			}
			
		}catch(InvalidKeySpecException e){
			throw new IllegalArgumentException("Error parsing public key: " +e.getMessage(), e);
		}


		List<ValidityRestriction> validityRestrictions = new ArrayList<ValidityRestriction>();
		validityRestrictions.add(new ValidityRestriction(new Time32(validFrom), new Time32(validTo)));
		if(geographicRegion != null){
			validityRestrictions.add(new ValidityRestriction(geographicRegion)); 
		}

		Certificate cert = new Certificate(signerInfos, subjectInfo, subjectAttributes, validityRestrictions);
				
		cert = signCertificate(cert, signingPublicKeyAlgorithm, caPrivateKey);

		return cert;
	}

	/**
	 * Method to convert a list of BigInteger
	 * @param itsAidList, list of BigIntegers, never null.
	 * @return a IntX version of the list.
	 */
	private List<Encodable> getIntXList(List<BigInteger> bigIntegerList) {
		ArrayList<Encodable> retval = new ArrayList<Encodable>();
		for(BigInteger v : bigIntegerList){
			retval.add(new IntX(v));
		}
		return retval;
	}
		
}
