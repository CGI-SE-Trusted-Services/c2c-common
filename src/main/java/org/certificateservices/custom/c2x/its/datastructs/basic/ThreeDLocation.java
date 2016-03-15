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
package org.certificateservices.custom.c2x.its.datastructs.basic;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;


/**
 * This structure defines how to specify a three dimensional location. latitude and longitude encode coordinate in
 * tenths of micro degrees relative to the World Geodetic System (WGS)-84 datum as defined in NIMA Technical
 * Report TR8350.2 [2].
 * The permitted values of latitude range from -900 000 000 to +900 000 000. The value 900 000 001 shall indicate
 * the latitude as not being available.
 * The permitted values of longitude range from -1 800 000 000 to +1 800 000 000. The value 1 800 000 001 shall
 * indicate the longitude as not being available.
 * elevation shall contain the elevation relative to the WGS-84 ellipsoid in decimeters. The value is interpreted as an
 * asymmetric signed integer with an encoding as follows:
 * <li> 0x0000 to 0xEFFF: positive numbers with a range from 0 to +6 143,9 meters. All numbers above +6 143,9 are
 * also represented by 0xEFFF.
 * <li> 0xF001 to 0xFFFF: negative numbers with a range from -409,5 to -0,1 meters. All numbers below -409,5 are
 * also represented by 0xF001.
 * <li> 0xF000: an unknown elevation.
 * EXAMPLES:
 * <li>0x0000 = 0 meters
 * <li>0x03E8 = 100 meters
 * <li>0xF7D1 = -209,5 meters (0xF001 + 0x07D0 = -409,5 meters + 200 meters)
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ThreeDLocation extends TwoDLocation{

	private int encodedElevation;
	
	
	/**
	 * Main constructor for TwoDLocation
	 * 

	 * @param latitude The permitted values of latitude range from -900 000 000 to +900 000 000. The value 900 000 001 shall indicate
     * the latitude as not being available.
	 * @param longitude The permitted values of longitude range from -1 800 000 000 to +1 800 000 000. The value 1 800 000 001 shall
     * indicate the longitude as not being available.
     * @param elevationDecimeters shall contain the elevation relative to the WGS-84 ellipsoid in decimeters.
     * 
     * @throws IllegalArgumentException if invalid latitude or longitude parameters where given.
	 */
	public ThreeDLocation(int latitude, int longitude, int elevationDecimeters) {
		super(latitude, longitude);
		if(elevationDecimeters >= 61439){
			encodedElevation = 0xEFFF;
		}else{
			if(elevationDecimeters <= -4095){
				encodedElevation = 0xF001;	
			}else{
			  if(encodedElevation < 0){
				  encodedElevation =  0xF001 + (4095 + elevationDecimeters);
			  }else{
				  encodedElevation = elevationDecimeters;
			  }
			}			
		}
	}

	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public ThreeDLocation(){
	}

	public int getEncodedElevation(){
		return encodedElevation;
	}
	
	public int getElevationInDecimeters(){
		if(encodedElevation <= 0xEFFF){
			return encodedElevation;
		}
		
		return -4095 + (encodedElevation - 0xF001);
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		super.encode(out);
		out.write(ByteBuffer.allocate(4).putInt(encodedElevation).array(),2,2);
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		super.decode(in);
		byte[] data = new byte[4];
		in.read(data,2,2);
		encodedElevation = ByteBuffer.wrap(data).getInt();
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + encodedElevation;
		return result;
	}


	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		ThreeDLocation other = (ThreeDLocation) obj;
		if (encodedElevation != other.encodedElevation)
			return false;
		return super.equals(obj);
	}


	@Override
	public String toString() {
		return "ThreeDLocation [encodedElevation=" + encodedElevation
				+ " ( " + getElevationInDecimeters() + " decimeters), latitude=" + latitude + ", longitude=" + longitude + "]";
	}

	
}
