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

import java.math.BigInteger;


/**
 * The longitude field contains an INTEGER encoding an estimate of the longitude with precision 1/10th microdegree relative to the 
 * World Geodetic System (WGS)-84 datum as defined in NIMA Technical Report TR8350.2.
 * <p>
 * The integer in the longitude field is no more than 1 800 000 000 and no less than -1 799 999 999.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class KnownLongitude extends OneEightyDegreeInt {

	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding.
	 */
	public KnownLongitude(){
		super();
		maxValue = BigInteger.valueOf(MAX);
	}
	
	/**
	 * Constructor used when encoding
	 * @param value between -900000000 and 900000000 (Unknown 900000001)
	 */
	public KnownLongitude(long value) {
		super(value);
		maxValue = BigInteger.valueOf(MAX);
	}

	@Override
	public String toString() {
		return "KnownLongitude [" + getValueAsLong() +"]";
	}
	
	
	
}
