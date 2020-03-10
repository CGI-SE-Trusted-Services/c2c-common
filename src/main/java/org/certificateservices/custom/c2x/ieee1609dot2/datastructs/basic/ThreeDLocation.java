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
 * This data structure contains an estimate of 3-D location. The details of the structure are given in the 
 * definitions of the individual fields below.
 * <p>
 * NOTE— The units used in this data structure are consistent with the location data structures used in [B20], 
 * though the encoding is incompatible.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ThreeDLocation extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int LATITUDE = 0;
	private static final int LONGITUDE = 1;
	private static final int ELEVATION = 2;

	/**
	 * Constructor used when decoding
	 */
	public ThreeDLocation(){
		super(false,3);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public ThreeDLocation(Latitude latitude, Longitude longitude, Elevation elevation) throws IOException{
		super(false,3);
		init();
		set(LATITUDE, latitude);
		set(LONGITUDE, longitude);
		set(ELEVATION, elevation);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public ThreeDLocation(long latitude, long longitude, int elevationDecimeters) throws IOException {
		super(false,3);
		init();
		set(LATITUDE, new Latitude(latitude));
		set(LONGITUDE, new Longitude(longitude));
		set(ELEVATION, new Elevation(elevationDecimeters));
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
	
	/**
	 * 
	 * @return the locations elevation
	 */
	public Elevation getElevation(){
		return (Elevation) get(ELEVATION);
	}
	
	
	private void init(){
		addField(LATITUDE, false, new Latitude(), null);
		addField(LONGITUDE, false, new Longitude(), null);
		addField(ELEVATION, false, new Elevation(), null);
	}
	
	@Override
	public String toString() {
		long latVal = getLatitude().getValueAsLong();
		long longVal = getLongitude().getValueAsLong();
		return "ThreeDLocation [latitude=" + (latVal != NinetyDegreeInt.UNKNOWN ? latVal : "UNKNOWN")+ ", longitude=" + (longVal != OneEightyDegreeInt.UNKNOWN ? longVal : "UNKNOWN") + ", elevation=" + getElevation().getElevationInDecimeters() + "]";
	}
	
}
