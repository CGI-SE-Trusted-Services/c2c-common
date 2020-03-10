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
 * This structure specifies a circle with its center at center, its radius given in meters, and located
 * tangential to the reference ellipsoid. The indicated region is all the points on the surface of the reference
 * ellipsoid whose distance to the center point over the reference ellipsoid is less than or equal to the radius. A
 * point which contains an elevation component is considered to be within the circular region if its horizontal
 * projection onto the reference ellipsoid lies within the region.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CircularRegion extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int CENTER = 0;
	private static final int RADIUS = 1;

	/**
	 * Constructor used when decoding
	 */
	public CircularRegion(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public CircularRegion(TwoDLocation center, int radiusInMeter) throws IOException {
		super(false,2);
		init();
		set(CENTER, center);
		set(RADIUS, new Uint16(radiusInMeter));
	}

	/**
	 * 
	 * @return the northwest position
	 */
	public TwoDLocation getCenter(){
		return (TwoDLocation) get(CENTER);
	}
	
	/**
	 * 
	 * @return the radius in meter
	 */
	public int getRadius(){
		return (int) ((Uint16) get(RADIUS)).getValueAsLong();
	}
	

	private void init(){
		addField(CENTER, false, new TwoDLocation(), null);
		addField(RADIUS, false, new Uint16(), null);
	}
	
	@Override
	public String toString() {
		return "CircularRegion [center=" + getCenter().toString().replace("TwoDLocation ", "") + ", radius=" +  getRadius() + "]";
	}
	
}
