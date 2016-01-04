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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.certificateservices.custom.c2x.common.Encodable;

/**
 * This value is used to identify data such as a certificate. It shall be calculated by first computing the SHA-256 hash of the
 * input data, and then taking the least significant X bytes from the hash output.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public abstract class HashedId implements Encodable{
	
	protected byte[] hashedId;
	
	/**
	 * Main constructor for a HashId taking the getHashLength() least significant bytes in it's hash value.
	 * 
	 * @param fullHashValue the full hash value.
	 */
	public HashedId(byte[] fullHashValue) throws IllegalArgumentException {
		if(fullHashValue.length < getHashLength()){
			throw new IllegalArgumentException("Error unsupported hash value, must be at least " + getHashLength() + " octets.");
		}
		
		hashedId = Arrays.copyOfRange(fullHashValue, fullHashValue.length - getHashLength() , fullHashValue.length);
	
	}
	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public HashedId(){
	}
	
	/** 
	 * @return the crlSeries value
	 */
	public byte[] getHashedId(){
		return hashedId;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(hashedId);		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		hashedId = new byte[getHashLength()];
		in.read(hashedId);
	}
	
	/**
	 * Required method defining the length of the Hash, example 8 or 3.
	 */
	protected abstract int getHashLength();

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(hashedId);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		HashedId other = (HashedId) obj;
		if (!Arrays.equals(hashedId, other.hashedId))
			return false;
		return true;
	}


}
