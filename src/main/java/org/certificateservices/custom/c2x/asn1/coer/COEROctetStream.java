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
package org.certificateservices.custom.c2x.asn1.coer;


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

/**
 * COER encoding of an octet stream
 * <p>
 * For more information see ISO/IEC 8825-7:2015 Section 14
 * 
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COEROctetStream implements COEREncodable{
	
	private static final long serialVersionUID = 1L;
	
	protected byte[] data;
	
	protected Integer lowerBound = null;
	protected Integer upperBound = null;
	
	/**
	 * Constructor when decoding an octet stream with no known lower or upper bounds.
	 */
	public COEROctetStream(){
	}
	
	/**
	 * Constructor when decoding an octet stream with known lower or upper bounds.
	 * 
	 * @param lowerBound the lower bound of the octet stream, null of not known.
	 * @param upperBound the upper bound of the octet stream, null of not known.
	 */
	public COEROctetStream(Integer lowerBound, Integer upperBound){
		this.lowerBound = lowerBound;
		this.upperBound = upperBound;
	}
	
	/**
	 * Constructor when encoding an octet stream with no known lower or upper bounds.
	 * 
	 * @param data the octed stream to encode.
	 */
	public COEROctetStream(byte[] data) {
		this.data = data;
	}
	
	/**
	 * Constructor when encoding an octet stream with known lower or upper bounds.
	 * 
	 * @param data the octed stream to encode.
	 * @param lowerBound the lower bound of the octet stream, null of not known.
	 * @param upperBound the upper bound of the octet stream, null of not known.
	 */
	public COEROctetStream(byte[] data, Integer lowerBound, Integer upperBound) throws IOException{
		this.data = data;
		this.lowerBound = lowerBound;
		this.upperBound = upperBound;
		
		if(data != null && lowerBound != null && data.length < lowerBound){
			throw new IOException("Error given data to octet stream is less than minimal value of " + lowerBound);
		}
		if(data != null && upperBound != null && data.length > upperBound){
			throw new IOException("Error given data to octet stream is larger than maximal value of " + upperBound);
		}
	}
	
	/**
	 * 
	 * @return the octed stream data.
	 */
	public byte[] getData() {
		return data;
	}
	
	/**
	 * 
	 * @return the lower bound of the octet stream, null of not known.
	 */
	public Integer getUpperBound() {
		return upperBound;
	}

	/**
	 * 
	 * @return the upper bound of the octet stream, null of not known.
	 */
	public Integer getLowerBound() {
		return lowerBound;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		if(data == null){
			throw new IOException("Data was null in octed stream.");
		}
		if(upperBound == null || lowerBound == null || upperBound != lowerBound){
			COEREncodeHelper.writeLengthDeterminant(data.length, out);
		}
		out.write(data);
	}
	
	@Override
	public void decode(DataInputStream in) throws IOException {
		Integer length = upperBound;
		if(upperBound == null || lowerBound == null || upperBound != lowerBound){
			length = COEREncodeHelper.readLengthDeterminantAsInt(in);
		}
		data = new byte[length];
		in.read(data);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(data);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof COEROctetStream))
			return false;
		COEROctetStream other = (COEROctetStream) obj;
		if (!Arrays.equals(data, other.data))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "COEROctetStream [data=" + new String(Hex.encode(data)) + "]";
	}

}
