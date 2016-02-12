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
 * A sequence of type RegionAndSubregions
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfRegionAndSubregions extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfRegionAndSubregions(){
		super(new RegionAndSubregions());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfRegionAndSubregions(RegionAndSubregions[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfRegionAndSubregions(List<RegionAndSubregions> sequenceValues){
		super((RegionAndSubregions[]) sequenceValues.toArray(new RegionAndSubregions[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		String retval = "SequenceOfRegionAndSubregions [";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("RegionAndSubregions ", "") + ",";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("RegionAndSubregions ", "");
			}
		}
		retval += "]";
		return retval;
	}
}
