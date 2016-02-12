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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.p2p;

import org.certificateservices.custom.c2x.asn1.coer.COERNull;

/**
 * CrlP2pPDU is a null value.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CrlP2pPDU extends COERNull {
	

	private static final long serialVersionUID = 1L;
	


	/**
	 * Constructor used when decoding and decoding
	 */
	public CrlP2pPDU(){
	}
	
	
	@Override
	public String toString() {
		return "CrlP2pPDU [NULL]";
	}
	
}
