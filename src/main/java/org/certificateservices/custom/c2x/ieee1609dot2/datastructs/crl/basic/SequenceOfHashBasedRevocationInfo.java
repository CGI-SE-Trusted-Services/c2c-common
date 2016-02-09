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
 * This structure is a sequence of HashBasedRevocationInfo
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfHashBasedRevocationInfo extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfHashBasedRevocationInfo(){
		super(new HashBasedRevocationInfo());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfHashBasedRevocationInfo(HashBasedRevocationInfo[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfHashBasedRevocationInfo(List<HashBasedRevocationInfo> sequenceValues){
		super((HashBasedRevocationInfo[]) sequenceValues.toArray(new HashBasedRevocationInfo[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		if(sequenceValues == null || size() == 0){
			return "SequenceOfHashBasedRevocationInfo []";
		}
		String retval = "SequenceOfHashBasedRevocationInfo [\n";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("HashBasedRevocationInfo ", "") + ",\n";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("HashBasedRevocationInfo ", "");
			}
		}
		retval = retval.replaceAll("\n", "\n  ");
		retval += "\n]";
		return retval;
	}
}
