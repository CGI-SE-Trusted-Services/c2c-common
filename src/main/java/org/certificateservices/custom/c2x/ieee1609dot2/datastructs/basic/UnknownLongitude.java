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
 * Unknown longitude with encoded value of 1800000001.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class UnknownLongitude extends OneEightyDegreeInt {

	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used for encoding and decoding.
	 */
	public UnknownLongitude()throws IOException {
		super(UNKNOWN);
	}
	


	@Override
	public String toString() {
		return "UnknownLongitude [UNKNOWN]";
	}
	
}
