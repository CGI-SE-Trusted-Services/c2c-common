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
import java.nio.ByteBuffer;

import org.certificateservices.custom.c2x.common.Encodable;

/**
 * This number identifies a CRL series.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CrlSeries implements Encodable{
	
	private long value;
	
	/**
	 * Main constructor for CrlSeries
	 * 
	 * @param value the value of the CrlSeries
	 */
	public CrlSeries(long value) {
		this.value = value;
	}
	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public CrlSeries(){
	}
	
	/** 
	 * @return the crlSeries value
	 */
	public long getValue(){
		return value;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(ByteBuffer.allocate(8).putLong(value).array(),4,4);		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		byte[] data = new byte[8];
		in.read(data,4,4);
		value = ByteBuffer.wrap(data).getLong();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (value ^ (value >>> 32));
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
		CrlSeries other = (CrlSeries) obj;
		if (value != other.value)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "CrlSeries [value=" + value + "]";
	}


}
