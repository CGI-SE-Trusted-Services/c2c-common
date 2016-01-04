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
 * This structure defines a circular region with radius given in meters and center at center. The region shall include
 * all points on the reference ellipsoid's surface with a distance smaller or equal than the radius to the center point.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CircularRegion implements Encodable{
	
	static final int MAX_RADIUS = 0xFFFF;

	private TwoDLocation center;
	private int radius;
	
	/**
	 * Main constructor for CircularRegion
	 * 
	 * @param center center coordinates of circle.
	 * @param radius given in meters (16 bit value)
	 */
	public CircularRegion(TwoDLocation center, int radius) {
		if(radius > MAX_RADIUS){
			throw new IllegalArgumentException("Invalid radius: " + radius + ", cannot be larger than " + MAX_RADIUS);
		}
		this.center = center;
		this.radius = radius;
	}

	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public CircularRegion(){
	}

	/**
	 * 
	 * @return  center coordinates of circle.
	 */
	public TwoDLocation getCenter(){
		return center;
	}
	
	/**
	 * 
	 * @return given in meters (16 bit value)
	 */
	public int getLongitude(){
		return radius;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		center.encode(out);
		out.write(ByteBuffer.allocate(4).putInt(radius).array(),2,2);
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		center = new TwoDLocation();
		center.decode(in);
		byte[] data = new byte[4];
		in.read(data,2,2);
		radius = ByteBuffer.wrap(data).getInt();
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((center == null) ? 0 : center.hashCode());
		result = prime * result + radius;
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
		CircularRegion other = (CircularRegion) obj;
		if (center == null) {
			if (other.center != null)
				return false;
		} else if (!center.equals(other.center))
			return false;
		if (radius != other.radius)
			return false;
		return true;
	}


	@Override
	public String toString() {
		return "CircularRegion [center=" + center + ", radius=" + radius + "]";
	}

}
