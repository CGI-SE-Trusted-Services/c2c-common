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
package org.certificateservices.custom.c2x.common;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;

/**
 * Common interface for all standards certificate implementation.
 * 
 * @author Philip Vendil
 *
 */
public interface Certificate {
	
	public enum Type{
		/**
		 * The certificate is an explicit certificate i.e has a signature and public key.
		 */
		EXPLICIT,
		/**
		 * The certificate is implicit, i.e has a reconstruction value.
		 */
		IMPLICIT
	}

	/**
	 * 
	 * @return indicates if the certificate is implicit or explicit.
	 */
	Type getCertificateType();
	
	/**
	 * Method to retrieve a java security compatible public key.
	 * 
	 * @param cryptoManager the related crypto manager, must be compatible with underlying implementation.
	 * @param alg the algorithm scheme used, algorithm indicator that specify Signature scheme used, such as SignatureChoices, PublicVerificationKeyChoices or PublicKeyAlgorithm
	 * @param signerCertificate the certificates signing certificate, only required for implicit certificate, otherwise null.
	 * @param signerPublicKey the java security public key if the signer certificate, only required for implicit certificates, otherwise it can be null.
	 * @return a public verification key of the certificate.
	 * @throws InvalidKeySpecException if the given signerPublicKey was invalid.
	 * @throws SignatureException if problems occurred reconstructing the public key.
	 * @throws BadArgumentException if supplied argument was invalid for the type of certificate.
	 */
	PublicKey getPublicKey(CryptoManager cryptoManager, AlgorithmIndicator alg, Certificate signerCertificate, PublicKey signerPublicKey) throws InvalidKeySpecException, SignatureException, BadArgumentException;
	
	/**
	 * 
	 * @return binary representation of the certificate.
	 * @throws IOException if encoding problems of the certificate occurred.
	 */
	byte[] getEncoded() throws IOException;

	/**
	 * Method to generate a HashedId8 Id for the Certifiate using SHA-256 digest.
	 * @param cryptoManager the related crypto manager, must be compatible with underlying implementation.
	 * @return a newly generated HashedId8
	 * @throws IOException if problem occurred encoding this certificate to byte array.
	 * @throws NoSuchAlgorithmException if SHA-256 algorithm wasn't found in given CryptoManager.
	 * @throws BadArgumentException if supplied argument was invalid for the type of certificate.
	 */
	HashedId8 asHashedId8(CryptoManager cryptoManager)
			throws IOException, NoSuchAlgorithmException;
}
