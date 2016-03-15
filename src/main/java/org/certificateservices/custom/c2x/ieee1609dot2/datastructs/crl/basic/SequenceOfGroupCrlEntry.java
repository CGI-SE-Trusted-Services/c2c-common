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
 * This structure is a sequence of GroupCrlEntry
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfGroupCrlEntry extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfGroupCrlEntry(){
		super(new GroupCrlEntry());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfGroupCrlEntry(GroupCrlEntry[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfGroupCrlEntry(List<GroupCrlEntry> sequenceValues){
		super((GroupCrlEntry[]) sequenceValues.toArray(new GroupCrlEntry[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		if(sequenceValues == null || size() == 0){
			return "SequenceOfGroupCrlEntry []";
		}
		String retval = "SequenceOfGroupCrlEntry [\n";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("GroupCrlEntry ", "") + ",\n";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("GroupCrlEntry ", "");
			}
		}
		retval = retval.replaceAll("\n", "\n  ");
		retval += "\n]";
		return retval;
	}
}
