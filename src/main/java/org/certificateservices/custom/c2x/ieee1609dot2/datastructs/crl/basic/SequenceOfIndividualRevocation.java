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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic;

import java.util.List;

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf;


/**
 * This structure is a sequence of IndividualRevocation
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfIndividualRevocation extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfIndividualRevocation(){
		super(new IndividualRevocation());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfIndividualRevocation(IndividualRevocation[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfIndividualRevocation(List<IndividualRevocation> sequenceValues){
		super((IndividualRevocation[]) sequenceValues.toArray(new IndividualRevocation[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		if(sequenceValues == null || size() == 0){
			return "SequenceOfIndividualRevocation []";
		}
		String retval = "SequenceOfIndividualRevocation [\n";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("IndividualRevocation ", "  ") + ",\n";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("IndividualRevocation ", "  ");
			}
		}
		retval += "\n]";
		return retval;
	}
}
