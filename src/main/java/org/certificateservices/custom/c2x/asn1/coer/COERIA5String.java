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

import org.bouncycastle.asn1.DERIA5String;

import java.io.IOException;

/**
 * COER Encoding class for encoding and decoding an IA5 String.
 * <p>
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COERIA5String extends COEROctetStream{

	private static final long serialVersionUID = 1L;

	/**
	 * Constructor used when decoding a string from IA5String and no lower or upper bounds are known.
	 */
	public COERIA5String() {
		super();
	}

	/**
	 * Constructor used when encoding a string to IA5String encoded format when the lower and upper bound of the string is known.
	 */
	public COERIA5String(String ia5String, Integer lowerBound, Integer upperBound) throws IOException {
		super(ia5String.getBytes(), lowerBound, upperBound);
		if(!DERIA5String.isIA5String(ia5String)){
			throw new IOException("Invalid IA5String characters in string: " + ia5String);
		}
	}

	/**
	 * Constructor used when encoding a string to ia5String format when no size bounds of the string is known.
	 */
	public COERIA5String(String ia5String) throws IOException {
		super(ia5String.getBytes("UTF-8"));
		if(!DERIA5String.isIA5String(ia5String)){
			throw new IOException("Invalid IA5String characters in string: " + ia5String);
		}
	}

	/**
	 * Constructor used for decoding when the lower and upper bounds of the string size is known.
	 */
	public COERIA5String(Integer lowerBound, Integer upperBound) {
		super(lowerBound, upperBound);
	}

	/**
	 * 
	 * @return the IA5 String inside the COER encoding.
	 */
	public String getAI5String() {
		return new String(getData());
	}

	/**
	 * Returns a displayable format of the content of the COEREncodable
	 * <p>
	 * <b>Important: this method does not return the UTF String data, use getAI5String() instead.</b>
	 */
	@Override
	public String toString() {
		return "COERIA5String [IA5String=" + getAI5String() + "]";
	}
	

}
