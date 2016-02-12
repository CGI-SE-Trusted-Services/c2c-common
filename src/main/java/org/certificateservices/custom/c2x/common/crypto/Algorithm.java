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

/**
 * Common enumeration of available key algorithms used by ITS and IEEE implementation.
 * 
 * Used to simplify the crypto manager implementation
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Algorithm {
	
	public enum Symmetric{
		aes128Ccm;	
	}
	
	public enum Signature{
		ecdsaNistP256,
		ecdsaBrainpoolP256r1;
		
		public int getFieldSize(){
			return 32;
		}
	}

	public enum Encryption{
	  ecies	
	}
	
	public enum Hash{
		// Hash algorithms
		sha256;
	}


	private Symmetric symmetric;
	private Signature signature;
	private Encryption encryption;
	private Hash hash;
	
	public Algorithm(Symmetric symmetric, Signature signature,
			Encryption encryption, Hash hash) {
		super();
		this.symmetric = symmetric;
		this.signature = signature;
		this.encryption = encryption;
		this.hash = hash;
	}
	
	/**
	 * @return the related symmetric algorithm
	 */
	public Symmetric getSymmetric() {
		return symmetric;
	}

	/**
	 * @return the related signature algorithm
	 */
	public Signature getSignature() {
		return signature;
	}

	/**
	 * @return the related encryption algorithm
	 */
	public Encryption getEncryption() {
		return encryption;
	}

	/**
	 * @return the related hash algorithm 
	 */
	public Hash getHash() {
		return hash;
	}
}
