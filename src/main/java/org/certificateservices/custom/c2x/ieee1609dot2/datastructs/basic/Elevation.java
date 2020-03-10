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


/**
 * Extends Elevation
 * 
 * @see ElevInt
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Elevation extends ElevInt {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public Elevation(){
		super();
	}
	
	/**
	 * Constructor used when encoding
	 * @param elevationDecimeters should be height in decimeters, between -4095 and 61439 
	 */
	public Elevation(int elevationDecimeters) {
		super(elevationDecimeters);
	}

	@Override
	public String toString() {
		return "Elevation [" + getElevationInDecimeters() + "(" + Integer.toString(getEncodedElevation(),16)+ ")"+ "]";
	}
}
