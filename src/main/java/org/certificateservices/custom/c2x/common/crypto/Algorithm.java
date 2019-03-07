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


import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.security.spec.ECParameterSpec;

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
		aes128Ccm(16,12);	
		
		
		private Symmetric(int keyLength, int nounceLength){
			this.keyLength = keyLength;
			this.nounceLength = nounceLength;
		}
		private int keyLength;
		private int nounceLength;
		
		/**
		 * 
		 * @return the length of symmetric key length
		 */
		public int getKeyLength(){
			return keyLength;
		}
		
		/**
		 * 
		 * @return the length of symmetric key length
		 */
		public int getNounceLength(){
			return nounceLength;
		}
	}
	
	public enum Signature{
		ecdsaNistP256("P-256",32),
		ecdsaBrainpoolP256r1("brainpoolP256r1",32),
		ecdsaBrainpoolP384r1("brainpoolP384r1",48);

		private String curveName;
		private int fieldSize;

		Signature(String curveName, int fieldSize){
			this.curveName = curveName;
			this.fieldSize = fieldSize;
		}

		public int getFieldSize(){
			return fieldSize;
		}

		public ECNamedCurveParameterSpec getECNamedCurveParameterSpec(){
			return ECNamedCurveTable.getParameterSpec(curveName);
		}

		// TODO
		public ECDomainParameters getECDomainParameters(){
			ECNamedCurveParameterSpec spec = getECNamedCurveParameterSpec();
			return new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
		}
	}

	public enum Encryption{
	  ecies	
	}
	
	public enum Hash{
		// Hash algorithms
		sha256,
		sha384
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
