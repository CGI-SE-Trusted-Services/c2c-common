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
 * Base type defining a sequence of uint3
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfUint3 extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfUint3(){
		super(new Uint3());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfUint3(Uint3[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfUint3(List<Uint3> sequenceValues){
		super((Uint3[]) sequenceValues.toArray(new Uint3[sequenceValues.size()]));
	}

	@Override
	public String toString() {
		String retval = "SequenceOfUint3 [";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += ((Uint3) sequenceValues[i]).getValueAsLong() + ",";
			}
			if(sequenceValues.length > 0){
				retval += ((Uint3) sequenceValues[sequenceValues.length-1]).getValueAsLong();
			}
		}
		retval += "]";
		return retval;
	}

	
}
