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

import org.certificateservices.custom.c2x.common.Encodable;


/**
 * This structure defines how to specify a two dimensional location. It is used to define validity regions of a certificate.
 * latitude and longitude encode a coordinate in tenths of micro degrees relative to the World Geodetic System
 * (WGS)-84 datum as defined in NIMA Technical Report TR8350.2 [2].
 * <p>
 * The permitted values of latitude range from -900 000 000 to +900 000 000. The value 900 000 001 shall indicate
 * the latitude as not being available.
 * <p>
 * The permitted values of longitude range from -1 800 000 000 to +1 800 000 000. The value 1 800 000 001 shall
 * indicate the longitude as not being available.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class TwoDLocation implements Encodable{

	protected int latitude;
	protected int longitude;
	
	/**
	 * Main constructor for TwoDLocation
	 * 

	 * @param latitude The permitted values of latitude range from -900 000 000 to +900 000 000. The value 900 000 001 shall indicate
     * the latitude as not being available.
	 * @param longitude The permitted values of longitude range from -1 800 000 000 to +1 800 000 000. The value 1 800 000 001 shall
     * indicate the longitude as not being available.
     * 
     * @throws IllegalArgumentException if invalid latitude or longitude parameters where given.
	 */
	public TwoDLocation(int latitude, int longitude) {
		if(latitude < -900000000 || latitude >  900000001){
			throw new IllegalArgumentException("Invalid latitude: " + latitude + " should be within -900 000 000 to +900 000 001");
		}
        if(longitude < -1800000000 || longitude > 1800000001){
        	throw new IllegalArgumentException("Invalid longitude: " + longitude + " should be within -1 800 000 000 to +1 800 000 001");
		}
		this.latitude = latitude;
		this.longitude = longitude;
	}

	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public TwoDLocation(){
	}

	/**
	 * 
	 * @return latitude range from -900 000 000 to +900 000 000. The value 900 000 001 shall indicate
     * the latitude as not being available.
	 */
	public int getLatitude(){
		return latitude;
	}
	
	/**
	 * 
	 * @return longitude range from -1 800 000 000 to +1 800 000 000. The value 1 800 000 001 shall
     * indicate the longitude as not being available.
	 */
	public int getLongitude(){
		return longitude;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(ByteBuffer.allocate(4).putInt(latitude).array());
		out.write(ByteBuffer.allocate(4).putInt(longitude).array());
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		byte[] data = new byte[4];
		in.read(data);
		latitude = ByteBuffer.wrap(data).getInt();
		in.read(data);
		longitude = ByteBuffer.wrap(data).getInt();
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + latitude;
		result = prime * result + longitude;
		return result;
	}


	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		TwoDLocation other = (TwoDLocation) obj;
		if (latitude != other.latitude)
			return false;
		if (longitude != other.longitude)
			return false;
		return true;
	}


	@Override
	public String toString() {
		return "TwoDLocation [latitude=" + latitude + ", longitude="
				+ longitude + "]";
	}



	
}
