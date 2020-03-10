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
 * This structure contains a linkage seed value for use in the algorithms specified in 5.1.3.4.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class LinkageSeed extends COEROctetStream{
	
	private static final int OCTETSTRING_SIZE = 16;
	private static final long serialVersionUID = 1L;
	
	
	/**
	 * Constructor used during decoding.
	 * 
	 */
	public LinkageSeed(){
		super(OCTETSTRING_SIZE, OCTETSTRING_SIZE);
	}
	
	/**
	 * Constructor used to create a linkageSeed.
	 * @param linkageSeed a 16 byte array.
	 * @throws IOException if linkageSeed was invalid
	 */
	public LinkageSeed(byte[] linkageSeed) throws IOException {
		super(linkageSeed, OCTETSTRING_SIZE, OCTETSTRING_SIZE);
	
	}
	
	/** 
	 * @return the linkage seed, same as getData() method.
	 */
	public byte[] getLinkageSeed(){
		return data;
	}
	
	@Override
	public String toString() {
		return "LinkageSeed [" + new String(Hex.encode(data)) + "]";
	}


}
