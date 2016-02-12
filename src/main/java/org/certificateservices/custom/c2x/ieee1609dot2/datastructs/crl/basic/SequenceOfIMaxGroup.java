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
 * This structure is a sequence of IMaxGroup
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfIMaxGroup extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfIMaxGroup(){
		super(new IMaxGroup());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfIMaxGroup(IMaxGroup[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfIMaxGroup(List<IMaxGroup> sequenceValues){
		super((IMaxGroup[]) sequenceValues.toArray(new IMaxGroup[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		if(sequenceValues == null || size() == 0){
			return "SequenceOfIMaxGroup []";
		}
		String retval = "SequenceOfIMaxGroup [\n";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("IMaxGroup ", "") + ",\n";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("IMaxGroup ", "");
			}
		}
		retval = retval.replaceAll("\n", "\n  ");
		retval += "\n]";
		return retval;
	}
}
