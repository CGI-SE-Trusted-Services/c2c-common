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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert;

import java.io.IOException;
import java.util.List;

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf;


/**
 * A sequence of type PsidGroupPermissions
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfPsidGroupPermissions extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfPsidGroupPermissions() {
		super(new PsidGroupPermissions());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfPsidGroupPermissions(PsidGroupPermissions[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfPsidGroupPermissions(List<PsidGroupPermissions> sequenceValues){
		super((PsidGroupPermissions[]) sequenceValues.toArray(new PsidGroupPermissions[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		String retval = "SequenceOfPsidGroupPermissions [";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString().replace("PsidGroupPermissions ", "") + ",";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString().replace("PsidGroupPermissions ", "");
			}
		}
		retval += "]";
		return retval;
	}
}
