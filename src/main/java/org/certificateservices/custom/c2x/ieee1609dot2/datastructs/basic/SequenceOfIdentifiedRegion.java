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
 * A sequence of type IdentifiedRegion
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfIdentifiedRegion extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfIdentifiedRegion(){
		super(new IdentifiedRegion());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfIdentifiedRegion(IdentifiedRegion[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfIdentifiedRegion(List<IdentifiedRegion> sequenceValues){
		super((IdentifiedRegion[]) sequenceValues.toArray(new IdentifiedRegion[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		String retval = "SequenceOfIdentifiedRegion [";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("IdentifiedRegion ", "") + ",";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("IdentifiedRegion ", "");
			}
		}
		retval += "]";
		return retval;
	}
}
