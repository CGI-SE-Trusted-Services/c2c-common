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
 * The longitude field contains an INTEGER encoding an estimate of the longitude with precision 1/10th microdegree relative to the 
 * World Geodetic System (WGS)-84 datum as defined in NIMA Technical Report TR8350.2.
 * <p>
 * The integer in the longitude field is no more than 1 800 000 000 and no less than -1 799 999 999, except that the 
 * value 1 800 000 001 is used to indicate that the longitude was not available to the sender.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class OneEightyDegreeInt extends COERInteger {

	private static final long serialVersionUID = 1L;
	
	public static final long MIN = -1799999999L;
	public static final long MAX = 1800000000L;
	public static final long UNKNOWN = 1800000001L;
	
	/**
	 * Constructor used when decoding.
	 */
	public OneEightyDegreeInt(){
		super(MIN, UNKNOWN);
	}
	
	/**
	 * Constructor used when encoding
	 * @param value between -1799999999 and 1800000000 (Unkown 1800000001)
	 */
	public OneEightyDegreeInt(long value) {
		super(value, MIN, UNKNOWN);
	}

	@Override
	public String toString() {
		long val = getValueAsLong();
		return "OneEightyDegreeInt [" + (val!= UNKNOWN ? val : "UNKNOWN") +"]";
	}
	
}
