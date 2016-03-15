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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc;

import java.util.List;

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf;


/**
 * A sequence of Receipient Info
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfRecipientInfo extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfRecipientInfo(){
		super(new RecipientInfo());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfRecipientInfo(RecipientInfo[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfRecipientInfo(List<RecipientInfo> sequenceValues){
		super((RecipientInfo[]) sequenceValues.toArray(new RecipientInfo[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		
		String retval = "SequenceOfRecipientInfo [";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("RecipientInfo ", "") + ",";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("RecipientInfo ", "");
			}
		}
		retval += "]";
		return retval;
	}
}
