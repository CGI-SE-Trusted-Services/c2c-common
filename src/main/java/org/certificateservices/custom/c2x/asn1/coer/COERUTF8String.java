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

import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * COER Encoding class for encoding and decoding an UTF-8 String.
 * <p>
 * For the UTF8String type, the octets shall be those specified in ISO/IEC 10646.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COERUTF8String extends COEROctetStream{
	
	private static final long serialVersionUID = 1L;

	/**
	 * Constructor used when decoding a string from UTF-8 and no lower or upper bounds are known.
	 */
	public COERUTF8String() {
		super();
	}

	/**
	 * Constructor used when encoding a string to UTF8 encoded format when the lower and upper bound of the string is known.
	 */
	public COERUTF8String(String utf8String, Integer lowerBound, Integer upperBound) throws IOException {
		super(utf8String.getBytes("UTF-8"), lowerBound, upperBound);
	}

	/**
	 * Constructor used when encoding a string to UTF8 encoded format when no size bounds of the string is known.
	 */
	public COERUTF8String(String utf8String) throws UnsupportedEncodingException {
		super(utf8String.getBytes("UTF-8"));
	}

	/**
	 * Constructor used for decoding when the lower and upper bounds of the string size is known.
	 */
	public COERUTF8String(Integer lowerBound, Integer upperBound) {
		super(lowerBound, upperBound);
	}

	/**
	 * 
	 * @return the UTF8 String inside the COER encoding.
	 */
	public String getUTF8String() {
		try {
			return new String(getData(),"UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Error unsupported encoding: UTF-8");
		}
	}

	/**
	 * Returns a displayable format of the content of the COEREncodable
	 * <p>
	 * <b>Important: this method does not return the UTF String data, use getUTF8String() instead.</b>
	 */
	@Override
	public String toString() {
		return "COERUTF8String [UTF8String=" + getUTF8String() + "]";
	}
	

}
