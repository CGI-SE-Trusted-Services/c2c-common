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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;

import java.io.IOException;

/**
 * This type represents the CRL PSID
 * <p>
 * PSID = 0x24, WW: this may need to change, just a placeholder 
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CrlPsid extends Psid {
	
	public static final int PSID = 0x24;
	
	private static final long serialVersionUID = 1L;
		
	/**
	 * Constructor used when encoding and decoding
	 * 
	 */
	public CrlPsid() throws IOException {
		super(PSID);
	}

	
	@Override
	public String toString() {
		return "CrlPsid [" + getValue().toString() + "(" + getValue().toString(16)+ ")"+ "]";
	}
}
