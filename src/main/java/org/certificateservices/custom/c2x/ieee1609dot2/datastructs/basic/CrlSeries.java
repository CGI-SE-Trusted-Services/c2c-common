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

/**
 * This integer identifies a series of CRLs issued under the authority of a particular CRACA.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CrlSeries extends Uint16 {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public CrlSeries(){
		super();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public CrlSeries(int crlSeries) throws IOException {
		super(crlSeries);		
	}
	
	@Override
	public String toString() {
		return "CrlSeries [" + getValueAsLong() + "]";
	}
}
