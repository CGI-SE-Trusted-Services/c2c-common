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

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

import java.io.IOException;

/**
 * This data structure is used to define validity regions for use in certificates. The 
 * latitude and longitude fields contain the latitude and longitude as defined above.
 * <p>
 * NOTE— This data structure is consistent with the location encoding used in [B20], except 
 * that values 900 000 001 for latitude (used to indicate that the latitude was not available) and 1 800 000 001 for longitude 
 * (used to indicate that the longitude was not available) are not valid.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class TwoDLocation extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int LATITUDE = 0;
	private static final int LONGITUDE = 1;

	/**
	 * Constructor used when decoding
	 */
	public TwoDLocation(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public TwoDLocation(Latitude latitude, Longitude longitude) throws IOException {
		super(false,2);
		init();
		set(LATITUDE, latitude);
		set(LONGITUDE, longitude);
		
		if((latitude != null && latitude.getValueAsLong() == Latitude.UNKNOWN) || 
		  (longitude != null && longitude.getValueAsLong() == Longitude.UNKNOWN )){
			throw new IOException("Error constructing TwoDLocation, UNKNOWN latitude or longitude is not valid for TwoDLocation");
		}
	}

	/**
	 * 
	 * @return the locations longitude
	 */
	public Longitude getLongitude(){
		return (Longitude) get(LONGITUDE);
	}
	
	/**
	 * 
	 * @return the locations latitude
	 */
	public Latitude getLatitude(){
		return (Latitude) get(LATITUDE);
	}
	

	private void init(){
		addField(LATITUDE, false, new Latitude(), null);
		addField(LONGITUDE, false, new Longitude(), null);
	}
	
	@Override
	public String toString() {
		long latVal = getLatitude().getValueAsLong();
		long longVal = getLongitude().getValueAsLong();
		return "TwoDLocation [latitude=" + latVal + ", longitude=" +  longVal + "]";
	}
	
}
