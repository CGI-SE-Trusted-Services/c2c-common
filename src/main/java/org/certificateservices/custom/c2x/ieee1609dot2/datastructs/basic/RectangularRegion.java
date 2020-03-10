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
 * This structure specifies a rectangle formed by connecting in sequence: (northWest.latitude,
 * northWest.longitude), (southEast.latitude, northWest.longitude),
 * (southEast.latitude, southEast.longitude), and (northWest.latitude,
 * southEast.longitude). The points are connected by lines of constant latitude or longitude. A point
 * which contains an elevation component is considered to be within the rectangular region if its horizontal
 * projection onto the reference ellipsoid lies within the region. A RectangularRegion is valid only if the
 * northWest value is north and west of the southEast value, i.e., the two points cannot have equal
 * latitude or equal longitude.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class RectangularRegion extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int NORTHWEST = 0;
	private static final int SOUTHEAST = 1;

	/**
	 * Constructor used when decoding
	 */
	public RectangularRegion(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 * @throws IOException if positions is equal
	 */
	public RectangularRegion(TwoDLocation northWest, TwoDLocation southEast) throws IOException {
		super(false,2);
		init();
		set(NORTHWEST, northWest);
		set(SOUTHEAST, southEast);
		
		if(northWest != null && northWest.equals(southEast)){
			throw new IOException("Error constructing RectangularRegion north west position cannot be the same as south east position.");
		}
	}

	/**
	 * 
	 * @return the northwest position
	 */
	public TwoDLocation getNorthWest(){
		return (TwoDLocation) get(NORTHWEST);
	}
	
	/**
	 * 
	 * @return the southeast position
	 */
	public TwoDLocation getSouthEast(){
		return (TwoDLocation) get(SOUTHEAST);
	}
	

	private void init(){
		addField(NORTHWEST, false, new TwoDLocation(), null);
		addField(SOUTHEAST, false, new TwoDLocation(), null);
	}
	
	@Override
	public String toString() {
		return "RectangularRegion [northwest=" + getNorthWest().toString().replace("TwoDLocation ", "") + ", southeast=" +  getSouthEast().toString().replace("TwoDLocation ", "") + "]";
	}
	
}
