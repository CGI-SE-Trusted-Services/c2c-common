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

import java.io.IOException;
import java.util.List;

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf;


/**
 * This data structure defines a region using a series of distinct geographic points, defined on the surface of
 * the reference ellipsoid. The region is specified by connecting the points in the order they appear, with each
 * pair of points connected by the geodesic on the reference ellipsoid. The polygon is completed by
 * connecting the final point to the first point. The allowed region is the interior of the polygon and its
 * boundary.
 * <p>
 * A point which contains an elevation component is considered to be within the polygonal region if its
 * horizontal projection onto the reference ellipsoid lies within the region.
 * </p>
 * <p>
 * A valid PolygonalRegion contains at least three points. In a valid PolygonalRegion, the implied lines that
 * make up the sides of the polygon do not intersect.
 * </p>
 * <p>
 *     <b>Critical information fields:</b>If present, this is a critical information field as defined in 5.2.5. An
 *     implementation that does not support the number of TwoDLocation in the PolygonalRegion when verifying a signed
 *     SPDU shall indicate that the signed SPDU is invalid. A compliant implementation shall support
 *     PolygonalRegions containing at least eight TwoDLocation entries.
 * </p>
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PolygonalRegion extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public PolygonalRegion(){
		super(new TwoDLocation());
	}
	
	/**
	 * Constructor used when encoding
	 * @param sequenceValues an array of at least 3 elements.
	 */
	public PolygonalRegion(TwoDLocation[] sequenceValues) throws IOException{
		super(sequenceValues);
		verify();
	}
	
	/**
	 * Constructor used when encoding
	 * @param sequenceValues a list of at least 3 elements.
	 */
	public PolygonalRegion(List<TwoDLocation> sequenceValues) throws IOException{
		super((TwoDLocation[]) sequenceValues.toArray(new TwoDLocation[sequenceValues.size()]));
		verify();
	}
	
	private void verify() throws IOException {
		if(sequenceValues.length < 3){
			throw new IOException("A PolygonalRegion must have a least 3 TwoDLocations");
		}
	}
	

	@Override
	public String toString() {
		String retval = "PolygonalRegion [";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("TwoDLocation ", "") + ",";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("TwoDLocation ", "");
			}
		}
		retval += "]";
		return retval;
	}
}
