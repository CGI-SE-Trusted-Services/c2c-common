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

/**
 * COER encoding of a null.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COERNull implements COEREncodable{
	
	private static final long serialVersionUID = 1L;
	
	
	/**
	 * Constructor used when encoding/decoding a COER boolean.
	 */
	public COERNull(){
	}

	@Override
	public int hashCode() {
		return 1;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		return true;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {

	}

	@Override
	public void decode(DataInputStream in) throws IOException {

	}

	@Override
	public String toString() {
		return "COERNull []";
	}
}
