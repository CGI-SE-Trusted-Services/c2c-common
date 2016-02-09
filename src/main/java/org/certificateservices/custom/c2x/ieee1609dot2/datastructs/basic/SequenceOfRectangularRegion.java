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

import java.util.List;

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf;


/**
 * This structure specifies a rectangle formed by connecting in sequence: (northWest.latitude, northWest.longitude), 
 * (southEast.latitude, northWest.longitude), (southEast.latitude, southEast.longitude), and (northWest.latitude, southEast.longitude). 
 * The points are connected by lines of constant latitude or longitude. A point 
 * which contains an elevation component is considered to be within the rectangular region if its horizontal projection 
 * onto the reference ellipsoid lies within the region.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfRectangularRegion extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfRectangularRegion(){
		super(new RectangularRegion());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfRectangularRegion(RectangularRegion[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfRectangularRegion(List<IdentifiedRegion> sequenceValues){
		super((RectangularRegion[]) sequenceValues.toArray(new RectangularRegion[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		String retval = "SequenceOfRectangularRegion [";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("RectangularRegion ", "") + ",";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("RectangularRegion ", "");
			}
		}
		retval += "]";
		return retval;
	}
}
