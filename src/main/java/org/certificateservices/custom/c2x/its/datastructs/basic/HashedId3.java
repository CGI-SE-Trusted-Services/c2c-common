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

import java.util.Arrays;


/**
 * This value is used to give an indication on an identifier, where real identification is not required. This can be used to
 * request a certificate from other surrounding stations. It shall be calculated by first computing the SHA-256 hash of the
 * input data, and then taking the least significant three bytes from the hash output. If a corresponding HashedId8 value
 * is available, it can be calculated by truncating the longer HashedId8 to the least significant three bytes.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class HashedId3 extends HashedId{
	
	/**
	 * Main constructor for a HashId taking the three least significant bytes in it's hash value.
	 * 
	 * @param fullHashValue the full hash value.
	 */
	public HashedId3(byte[] fullHashValue){
		super(fullHashValue);
	}
	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public HashedId3(){
		super();
	}

	/**
	 * Indicates this is an eight octet hashId
	 */
	@Override
	protected int getHashLength() {
		return 3;
	}

	@Override
	public String toString() {
		return "HashedId3 [hashedId=" + Arrays.toString(hashedId) + "]";
	}
	

}
