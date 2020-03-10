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

import org.certificateservices.custom.c2x.asn1.coer.COERInteger;

import java.io.IOException;

/**
 * Base type defining integer between 0 and 4294967295 (0xff ff ff ff)
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Uint32 extends COERInteger {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public Uint32(){
		super(0,4294967295L);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public Uint32(long value)  {
		super(value,0,4294967295L);
	}
	

	@Override
	public String toString() {
		return "Uint32 [" + value + "]";
	}

}
