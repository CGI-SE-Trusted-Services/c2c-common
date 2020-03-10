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
 * The elevation field represents the geographic position above or below the WGS84 ellipsoid. The 16-bit value is 
 * interpreted as an integer number of decimeters and represents an asymmetric range of positive and negative values. 
 * The encoding is as follows: the range 0x0000 to 0xEFFF (0 to 61439 decimal) are positive numbers representing 
 * elevations from 0 to +6143.9 m (i.e., above the reference ellipsoid). The range 0xF001 to 0xFFFF are negative 
 * numbers representing elevations from –409.5 m to –0.1 m (i.e., below the reference ellipsoid). An elevation
 * higher than +6143.9 m is represented 0xEFFF. An elevation lower than –409.5 m is represented 0xF001. 
 * An elevation data element of 0xF000 corresponds to unknown elevation.
 * 
 * Examples of this encoding are: the elevation 0 m is encoded as 0x0000. 
 * The elevation –0.1 m is encoded as 0xFFFF. 
 * The elevation +100.0 meters is encoded as 0x03E8.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ElevInt extends Uint16 {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public ElevInt(){
		super();
	}
	
	/**
	 * Constructor used when encoding
	 * @param elevationDecimeters should be height in decimeters, between -4095 and 61439 
	 */
	public ElevInt(int elevationDecimeters) {
		long encodedElevation;
		if(elevationDecimeters >= 61439){
			encodedElevation = 0xEFFF;
		}else{
			if(elevationDecimeters <= -4095){
				encodedElevation = 0xF001;	
			}else{
			  if(elevationDecimeters < 0){
				  encodedElevation =  0xF001 + (4095 + elevationDecimeters);
			  }else{
				  encodedElevation = elevationDecimeters;
			  }
			}			
		}
		
		this.value = BigInteger.valueOf(encodedElevation);
		
		
	}
	
	/**
	 * 
	 * @return the encoded elevation value.
	 */
	public int getEncodedElevation(){
		return (int) getValueAsLong();
	}
	
	/**
	 * 
	 * @return the elevation id decimeters between -4095 and 61439
	 */
	public int getElevationInDecimeters(){
		int encodedElevation = getEncodedElevation();
		if(encodedElevation <= 0xEFFF){
			return encodedElevation;
		}
		
		return -4095 + (encodedElevation - 0xF001);
	}
	
	@Override
	public String toString() {
		return "ElevInt [" + getElevationInDecimeters() + "(" + Integer.toString(getEncodedElevation(),16)+ ")"+ "]";
	}
}
