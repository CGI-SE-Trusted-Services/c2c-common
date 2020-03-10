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
 * This is the individual linkage value. See 5.1.3 and 7.3 for details of use.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class LinkageValue extends COEROctetStream{
	
	private static final int OCTETSTRING_SIZE = 9;
	private static final long serialVersionUID = 1L;
	
	
	/**
	 * Constructor used during decoding.
	 * 
	 */
	public LinkageValue(){
		super(OCTETSTRING_SIZE, OCTETSTRING_SIZE);
	}
	
	/**
	 * Constructor used to create a linkageValue value.
	 * @param linkageValue a 9 byte array.
	 * @throws IOException if linkageValue was invalid
	 */
	public LinkageValue(byte[] linkageValue) throws IOException {
		super(linkageValue, OCTETSTRING_SIZE, OCTETSTRING_SIZE);
	
	}
	
	/** 
	 * @return the linkage value, same as getData() method.
	 */
	public byte[] getLinkageValue(){
		return data;
	}
	
	@Override
	public String toString() {
		return "LinkageValue [" + new String(Hex.encode(data)) + "]";
	}


}
