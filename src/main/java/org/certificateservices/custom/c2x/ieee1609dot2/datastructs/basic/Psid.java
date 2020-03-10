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
import java.math.BigInteger;

import org.certificateservices.custom.c2x.asn1.coer.COERInteger;

/**
 * This type represents the PSID defined in IEEE Std 1609.12.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Psid extends COERInteger {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public Psid(){
		super(BigInteger.ZERO,null);
	}
	
	/**
	 * Constructor used when encoding
	 * @param psidValue the integer value of the psid
	 */
	public Psid(long psidValue) throws IllegalArgumentException {
		super(BigInteger.valueOf(psidValue),BigInteger.ZERO,null);
	}
	
	/**
	 * Constructor used when encoding
	 * @param psidValueHex psid value in hex format
	 * @throws NumberFormatException if invalid HEX string was given.
	 * @throws IOException if encoding problems occurred.
	 */
	public Psid(String psidValueHex) throws IllegalArgumentException, NumberFormatException{
		super(new BigInteger(psidValueHex, 16),BigInteger.ZERO,null);
	}
	
	@Override
	public String toString() {
		return "Psid [" + getValue().toString() + "(" + getValue().toString(16)+ ")"+ "]";
	}
}
