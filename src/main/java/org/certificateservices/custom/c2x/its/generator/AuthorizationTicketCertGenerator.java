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
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfoType;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType;

/**
 * Certificate Generator class for generating a authorization ticket certificates.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class AuthorizationTicketCertGenerator extends BaseCertGenerator {

	
	private Certificate authorizationCA;
	private PrivateKey authorizationCAPrivateKey;
	
	/**
	 * Main creating a instance of a authorization ticket certificate generator for one authorization authority.
	 * 
	 * @param cryptoManager the crypto manager to use.
	 * @param authorizationCA the CA certificate of the authorization CA to use.
	 * @param authorizationCAPrivateKey the private key of the authorization CA.
	 * 
	 */
	public AuthorizationTicketCertGenerator(ITSCryptoManager cryptoManager, Certificate authorizationCA, PrivateKey authorizationCAPrivateKey) {
		super(cryptoManager);
		this.authorizationCA = authorizationCA;
		this.authorizationCAPrivateKey = authorizationCAPrivateKey;
	}
	
	/**
	 * Constructor where it is possible to specify the certificate version to use.
	 * 
	 * @param certificateVersion the version to generate certificates for see Certificate.CERTIFICATE_VERSION_ constants.
	 * @param cryptoManager the crypto manager to use.
	 * @param authorizationCA the CA certificate of the authorization CA to use.
	 * @param authorizationCAPrivateKey the private key of the authorization CA.
	 * 
	 */
	public AuthorizationTicketCertGenerator(int certificateVersion, ITSCryptoManager cryptoManager, Certificate authorizationCA, PrivateKey authorizationCAPrivateKey) {
		super(certificateVersion, cryptoManager);
		this.authorizationCA = authorizationCA;
		this.authorizationCAPrivateKey = authorizationCAPrivateKey;
	}


	/**
	 * Method to generate an Authorization Ticket using one of the signer infos certificate_digest_with_ecdsap256 or certificate
	 * 
	 * @param signerInfoType one of certificate_digest_with_ecdsap256 or certificate
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
	public Certificate genAuthorizationTicket(
			SignerInfoType signerInfoType,
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
				if(certificateVersion != Certificate.CERTIFICATE_VERSION_1){
				  throw new IllegalArgumentException("Invalid signer info type certificate is not supported for version 2 certificates");	
				}else{
				  signerInfo = new SignerInfo(authorizationCA);
				}
			}else{
				try {
					HashedId8 hash = new HashedId8(authorizationCA,cryptoManager);
					signerInfo = new SignerInfo(hash);
				} catch (NoSuchAlgorithmException e) {
					throw new SignatureException("Error generating certificate, no such algorithm: " + e.getMessage(),e);
				} catch (InvalidKeySpecException e) {
					throw new SignatureException("Error generating certificate, invalid key: " + e.getMessage(),e);
				}				
			}
		
			return genCert(signerInfo, SubjectType.authorization_ticket, null, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, authorizationCAPrivateKey, authorizationCA);
		}
		throw new IllegalArgumentException("Unsupported signer info type: " + signerInfoType);

	}
	
	/**
	 * Method to generate an Authorization Ticket using signer info  certificate_chain.
	 * 
	 * <b>Important</b>:only supported for version 1 certificates.
	 * 
	 * @param signerInfoCAChain the certificate chain to include in the signer info. The last element of the chain shall contain 
	 * the certificate used to sign the message, the next to last element shall contain the certificate of the CA that signed the 
	 * last certificate and so on. The first element of the chain needs not be a root certificate.
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
	public Certificate genAuthorizationTicket(
			List<Certificate> signerInfoCAChain,
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
		if(certificateVersion != Certificate.CERTIFICATE_VERSION_1){
			throw new IllegalArgumentException("Authorization ticket with certificate chain as signer info is only supported for version 1 certificates");
		}
		SignerInfo signerInfo = new SignerInfo(signerInfoCAChain);					
		return genCert(signerInfo, SubjectType.authorization_ticket, null, itsAidList, assuranceLevel, confidenceLevel, validFrom, validTo, geographicRegion, signingPublicKeyAlgorithm, signPublicKey, encPublicKeyAlgorithm, encPublicKey, authorizationCAPrivateKey, authorizationCA);
	}



}
