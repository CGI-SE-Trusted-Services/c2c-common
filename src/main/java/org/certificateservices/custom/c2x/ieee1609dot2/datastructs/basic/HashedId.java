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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic;

import java.io.IOException;
import java.util.Arrays;

import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;

/**
 * Abstract base class for all HasedIdX types.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public abstract class HashedId extends COEROctetStream{
	
	private static final long serialVersionUID = 1L;
	
	
	/**
	 * Constructor used during decoding.
	 * 
	 */
	public HashedId(){
		lowerBound=getHashLength();
		upperBound=getHashLength();
	}
	
	/**
	 * Constructor used to create a hashedid value for a full hash byte array.
	 * @param fullHashValue the fill hash value.
	 * @throws IOException if full hash value was shorted that hash length
	 */
	public HashedId(byte[] fullHashValue) throws IOException {
		lowerBound=getHashLength();
		upperBound=getHashLength();
		
		if(fullHashValue.length < getHashLength()){
			throw new IOException("Error unsupported hash value, must be at least " + getHashLength() + " octets.");
		}
		
		data = Arrays.copyOfRange(fullHashValue, fullHashValue.length - getHashLength() , fullHashValue.length);
	
	}
	
	/** 
	 * @return the hash id value, same as getData() method.
	 */
	public byte[] getHashedId(){
		return data;
	}
	
	/**
	 * Required method defining the length of the Hash, example 8 or 3.
	 */
	protected abstract int getHashLength();

}
