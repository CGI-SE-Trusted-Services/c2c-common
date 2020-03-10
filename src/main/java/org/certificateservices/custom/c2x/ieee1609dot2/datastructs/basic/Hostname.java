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
import java.io.UnsupportedEncodingException;

import org.certificateservices.custom.c2x.asn1.coer.COERUTF8String;

/**
 * This is a UTF-8 string as defined in IETF RFC 3629. The contents are determined by policy.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Hostname extends COERUTF8String {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public Hostname(){
		super(0,255);
	}
	
	/**
	 * Constructor used when encoding
	 * 
	 * @throws IOException if UTF 8 encoding isn't supported.
	 */
	public Hostname(String hostname) throws IOException {
		super(hostname,0,255);
	}

	@Override
	public String toString() {
		return "Hostname [" + getUTF8String() + "]";
	}
	

}
