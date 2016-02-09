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
 * This structure is a sequence of JMaxGroup
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfJMaxGroup extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfJMaxGroup(){
		super(new JMaxGroup());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfJMaxGroup(JMaxGroup[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfJMaxGroup(List<JMaxGroup> sequenceValues){
		super((JMaxGroup[]) sequenceValues.toArray(new JMaxGroup[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		if(sequenceValues == null || size() == 0){
			return "SequenceOfJMaxGroup []";
		}
		String retval = "SequenceOfJMaxGroup [\n";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("JMaxGroup ", "") + ",\n";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("JMaxGroup ", "");
			}
		}
		retval = retval.replaceAll("\n", "\n  ");
		retval += "\n]";
		return retval;
	}
}
