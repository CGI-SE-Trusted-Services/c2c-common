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

import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf;


/**
 * A sequence of type SequenceOfOctetString
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfOctetString extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfOctetString(){
		super(new COEROctetStream());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfOctetString(COEROctetStream[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfOctetString(List<COEROctetStream> sequenceValues){
		super((COEROctetStream[]) sequenceValues.toArray(new COEROctetStream[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		String retval = "SequenceOfOctetString [";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i]+ ",";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1];
			}
		}
		retval += "]";
		return retval;
	}
}
