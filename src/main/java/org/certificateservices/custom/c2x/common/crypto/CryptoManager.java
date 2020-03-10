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
package org.certificateservices.custom.c2x.common.crypto;

import org.certificateservices.custom.c2x.common.BadArgumentException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import javax.crypto.SecretKey;


/**
 * Base interface for CryptoManager containing common methods for both ETSI ITS and IEEE
 * standards.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public interface CryptoManager {
	
	/**
	 * Method that needs to be called before any calls to the crypto manager is performed, it
	 * should initialize all underlying components with the supplied paramteters. 
	 *  
	 * @throws BadArgumentException if supplied parameters contained invalid data.
	 * @throws NoSuchAlgorithmException if required underlying cryptographic algorithms doesn't exist in JVM.
	 * @throws NoSuchProviderException if required cryptographic providers couldn't be found in JVM.
	 * @throws IOException if communication problems occurred with underlying components.
	 * @throws BadCredentialsException if supplied credentials wasn't successful when authentication towards underlying hardware.
	 * @throws SignatureException  If internal problems occurred initializing the cryptomanager.
	 */
	void setupAndConnect(CryptoManagerParams params) throws BadArgumentException, NoSuchAlgorithmException, NoSuchProviderException, IOException, BadCredentialsException, SignatureException;

	/**
	 * Method to generate a new key pair for the given public key algorithm scheme.
	 * 
	 * @param alg the type of key to generate
	 * 
	 * @return a new key pair.
	 * 
	 * @throws BadArgumentException if supplied arguments was invalid.
	 * @throws IOException if communication problems occurred with underlying components.
	 * @throws InvalidKeyException if other non-IO related problems occurred generating the key. 
	 */
	KeyPair generateKeyPair(AlgorithmIndicator alg) throws BadArgumentException, IOException,InvalidKeyException;
	
	/**
	 * Method to generate a new symmetric secret key for the given algorithm scheme.
	 * 
	 * @param alg the type of key to generate
	 * 
	 * @return a new secret key pair.
	 * 
	 * @throws BadArgumentException if supplied arguments was invalid.
	 * @throws IOException if communication problems occurred with underlying components.
	 * @throws InvalidKeyException if other non-IO related problems occurred generating the key. 
	 */
	SecretKey generateSecretKey(AlgorithmIndicator alg) throws BadArgumentException, IOException,InvalidKeyException;
	
	/**
	 * Method to generate a digest of a message using the given hash algorithm scheme.
	 * 
	 * @param message the message data to generate a digest from.
	 * @param alg the related hash algorithm scheme to use.
	 * @return a digest of the message.
	 * 
	 * @throws BadArgumentException if an unsupported public key algorithm scheme was given.
	 * @throws NoSuchAlgorithmException if related cryptographic algorithm wasn't available in JVM.
	 */
	byte[] digest(byte[] message, AlgorithmIndicator alg) throws BadArgumentException, NoSuchAlgorithmException;
	
	/**
	 * Method signaling to underlying components to release resources.
	 * 
	 * @throws IOException if communication problems occurred with underlying components.
	 */
	void disconnect() throws IOException;
	

}
