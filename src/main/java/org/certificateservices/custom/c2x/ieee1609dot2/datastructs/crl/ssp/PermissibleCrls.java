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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.ssp;

import java.util.List;

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries;


/**
 * This type is used to determine the validity of the crlSeries field in the CrlContents structure. The
 * crlSeries field in the CrlContents structure is invalid unless that value appears as an entry in the
 * SEQUENCE contained in this field.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PermissibleCrls extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public PermissibleCrls(){
		super(new CrlSeries());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public PermissibleCrls(CrlSeries[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public PermissibleCrls(List<CrlSeries> sequenceValues){
		super((CrlSeries[]) sequenceValues.toArray(new CrlSeries[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		if(sequenceValues == null || size() == 0){
			return "PermissibleCrls []";
		}
		String retval = "PermissibleCrls [";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("CrlSeries ", "") + ",";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("CrlSeries ", "");
			}
		}
		retval += "]";
		return retval;
	}
}
