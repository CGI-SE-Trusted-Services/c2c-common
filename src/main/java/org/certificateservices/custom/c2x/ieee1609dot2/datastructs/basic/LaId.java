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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;

import java.io.IOException;

/**
 * This structure contains a LA Identifier for use in the algorithms specified in 5.1.3.4.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class LaId extends COEROctetStream{
	
	private static final int OCTETSTRING_SIZE = 2;
	private static final long serialVersionUID = 1L;
	
	
	/**
	 * Constructor used during decoding.
	 * 
	 */
	public LaId(){
		super(OCTETSTRING_SIZE, OCTETSTRING_SIZE);
	}
	
	/**
	 * Constructor used to create a LaId.
	 * @param laId a 2 byte array.
	 * @throws IOException if laId was invalid
	 */
	public LaId(byte[] laId) throws IOException {
		super(laId, OCTETSTRING_SIZE, OCTETSTRING_SIZE);
	
	}
	
	/** 
	 * @return the linkage value, same as getData() method.
	 */
	public byte[] getLaId(){
		return data;
	}
	
	@Override
	public String toString() {
		return "LaId [" + new String(Hex.encode(data)) + "]";
	}


}
