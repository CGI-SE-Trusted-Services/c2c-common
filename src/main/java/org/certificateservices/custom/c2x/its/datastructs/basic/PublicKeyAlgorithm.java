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
package org.certificateservices.custom.c2x.its.datastructs.basic;

import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.common.crypto.Algorithm.Encryption;
import org.certificateservices.custom.c2x.common.crypto.Algorithm.Hash;
import org.certificateservices.custom.c2x.common.crypto.Algorithm.Signature;
import org.certificateservices.custom.c2x.common.crypto.Algorithm.Symmetric;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;


/**
 * <code>
 * enum {
 *  ecdsa_nistp256_with_sha256(0),
 *  ecies_nistp256(1),
 *  reserved(240..255),
 *  (2^8-1)
 * } PublicKeyAlgorithm;
 * </code>
 * <p>
 * This enumeration lists supported algorithms based on public key cryptography. Values in the range of 240 to 255 shall
 * not be used as they are reserved for internal testing purposes.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum PublicKeyAlgorithm implements AlgorithmIndicator{
	ecdsa_nistp256_with_sha256( 0, 32, null),
	ecies_nistp256( 1, 32, SymmetricAlgorithm.aes_128_ccm);  
	
	private int byteValue;
	private int fieldSize;
	private SymmetricAlgorithm relatedSymmetricAlgorithm;
	
	PublicKeyAlgorithm(int byteValue, int fieldSize, SymmetricAlgorithm relatedSymmetricAlgorithm){
		this.byteValue = byteValue;
		this.fieldSize = fieldSize;
		this.relatedSymmetricAlgorithm = relatedSymmetricAlgorithm;
	}
	
	public int getByteValue(){
		return byteValue;
	}
	
	
	public int getFieldSize() throws UnsupportedOperationException{
		if(fieldSize == 0){
			throw new UnsupportedOperationException("Error: unspecified Public Key Algorithm field size");
		}
		return fieldSize;
	}
	
	/**
	 * 
	 * @return the related symmetric algorithm associated with this public key algorithm identifier.
	 * @throws UnsupportedOperationException if no related symmetric algorithm exists.
	 */
	public SymmetricAlgorithm getRelatedSymmetricAlgorithm() throws UnsupportedOperationException{
		if(relatedSymmetricAlgorithm == null){
			throw new UnsupportedOperationException("Error:  Public Key Algorithm has no related symmetric algorithm");
		}
		return relatedSymmetricAlgorithm;
	}
	
	/**
	 * Method returning a Public Key Algorithm by it's byte value.
	 */
	public static PublicKeyAlgorithm getByValue(int value){
		for(PublicKeyAlgorithm next : PublicKeyAlgorithm.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}

	@Override
	public Algorithm getAlgorithm() {
		switch (this) {
		case ecdsa_nistp256_with_sha256:
			return new Algorithm(null, Signature.ecdsaNistP256, null, Hash.sha256);
		case ecies_nistp256:
			return new Algorithm(Symmetric.aes128Ccm, Signature.ecdsaNistP256, Encryption.ecies, Hash.sha256);
		default:
			throw new IllegalArgumentException("Unsupported algorithm: " + this);
		}
	}
	
	

}