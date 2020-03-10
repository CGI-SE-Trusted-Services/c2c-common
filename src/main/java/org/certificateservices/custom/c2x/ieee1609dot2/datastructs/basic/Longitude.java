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
 * The longitude field contains an INTEGER encoding an estimate of the longitude with precision 1/10th microdegree relative to the 
 * World Geodetic System (WGS)-84 datum as defined in NIMA Technical Report TR8350.2.
 * <p>
 * The integer in the longitude field is no more than 1 800 000 000 and no less than -1 799 999 999, except that the 
 * value 1 800 000 001 is used to indicate that the longitude was not available to the sender.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Longitude extends OneEightyDegreeInt {

	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding.
	 */
	public Longitude() {
		super();
	}

	/**
	 * Constructor used when encoding
	 * @param value no more than 1 800 000 000 and no less than -1 799 999 999 or 1 800 000 001 for UNKNOWN
	 */
	public Longitude(long value) throws IOException {
		super(value);
	}

	@Override
	public String toString() {
		long val = getValueAsLong();
		return "Longitude [" + (val!= UNKNOWN ? val : "UNKNOWN") +"]";
	}
	
}
