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
 * This value is used to identify data such as a certificate. It shall be calculated by first computing the SHA-256 hash of the
 * input data, and then taking the least significant eight bytes from the hash output.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class HashedId8 extends HashedId{

	/**
	 * Main constructor for a HashId taking the eight least significant bytes in it's hash value.
	 * 
	 * @param fullHashValue the full hash value.
	 */
	public HashedId8(byte[] fullHashValue){
		super(fullHashValue);
	}
	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public HashedId8(){
		super();
	}
	
	/**
	 * Indicates this is an eight octet hashId
	 */
	@Override
	protected int getHashLength() {
		return 8;
	}

	@Override
	public String toString() {
		return "HashedId8 [hashedId=" + Arrays.toString(hashedId) + "]";
	}
	
}
