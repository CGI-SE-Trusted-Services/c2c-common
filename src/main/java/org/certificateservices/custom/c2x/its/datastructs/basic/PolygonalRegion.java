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
import java.util.List;

import org.certificateservices.custom.c2x.common.EncodeHelper;
import org.certificateservices.custom.c2x.common.Encodable;


/**
 * This variable-length vector describes a region by enumerating points on the region's boundary. The points shall be
 * linked to each other, with the last point linked to the first. No intersections shall occur and no more than 12 points shall
 * be given. The specified region shall be continuous and shall not contain holes.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PolygonalRegion implements Encodable{
	
	static final int MAX_POINTS = 12;
	
	private List<TwoDLocation> points;
	
	/**
	 * Main constructor for PolygonalRegion
	 * 
	 * @param points a list of coordinate points. The points shall be linked to each other, with the last point linked 
	 * to the first. No intersections shall occur and no more than 12 points shall be given. The specified region 
	 * shall be continuous and shall not contain holes.
	 * @throws IllegalArgumentException if to many points where given in the list.
	 */
	public PolygonalRegion(List<TwoDLocation> points) throws IllegalArgumentException{
		if(points.size() > MAX_POINTS){
			throw new  IllegalArgumentException("Invalid number of points in Polygonal Region " + points.size()  + " not more than "+ MAX_POINTS + " supported");
		}
		this.points = points;
	}

	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public PolygonalRegion(){
	}

	/**
	 * 
	 * @return  a list of coordinate points marking the polygonal region.
	 */
	public List<TwoDLocation> getPoints(){
		return points;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		EncodeHelper.encodeVariableSizeVector(out, points);
	}

	@SuppressWarnings("unchecked")
	@Override
	public void decode(DataInputStream in) throws IOException {
		points = (List<TwoDLocation>) EncodeHelper.decodeVariableSizeVector(in, TwoDLocation.class);
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((points == null) ? 0 : points.hashCode());
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
		PolygonalRegion other = (PolygonalRegion) obj;
		if (points == null) {
			if (other.points != null)
				return false;
		} else if (!points.equals(other.points))
			return false;
		return true;
	}


	@Override
	public String toString() {
		return "PolygonalRegion [points=" + points + "]";
	}


}
