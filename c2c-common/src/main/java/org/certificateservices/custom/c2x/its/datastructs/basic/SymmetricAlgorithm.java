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


/**
 * <code>
 * enum {
 *   aes_128_ccm (0),
 *   reserved (240..255),
 *   (2^8-1)
 * } SymmetricAlgorithm;
 * </code>
 * <p>
 * This enumeration lists supported algorithms based on symmetric key cryptography. Values in the range of 240 to 255
 * shall not be used as they are reserved for internal testing purposes. The algorithm aes_128_ccm denotes the
 * symmetric key cryptography algorithm AES-CCM as specified in NIST SP 800-38C [4].
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum SymmetricAlgorithm {
	aes_128_ccm( 0, 16);
	
	private int byteValue;
	private int keyLength;
	
	SymmetricAlgorithm(int byteValue, int keyLength){
		this.byteValue = byteValue;
		this.keyLength = keyLength;
	}
	
	public int getByteValue(){
		return byteValue;
	}
	
	public int getKeyLength(){
		return keyLength;
	}
	
	/**
	 * Method returning a SymmetricAlgorithm by it's byte value.
	 */
	public static SymmetricAlgorithm getByValue(int value){
		for(SymmetricAlgorithm next : SymmetricAlgorithm.values()){
			if(next.byteValue == value){
				return next;
			}
		}
		return null;
	}

}