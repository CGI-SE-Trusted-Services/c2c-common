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

import java.util.List;

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf;


/**
 * This structure is a profile of the structure CertificateBase which specifies the valid 
 * combinations of fields to transmit implicit and explicit certificates.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SequenceOfCertificate extends COERSequenceOf {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public SequenceOfCertificate(){
		super(new Certificate());
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfCertificate(Certificate[] sequenceValues){
		super(sequenceValues);
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SequenceOfCertificate(List<Certificate> sequenceValues){
		super((Certificate[]) sequenceValues.toArray(new Certificate[sequenceValues.size()]));
	}
	

	@Override
	public String toString() {
		if(sequenceValues == null || size() == 0){
			return "SequenceOfCertificate []";
		}
		String retval = "SequenceOfCertificate [\n";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				retval += sequenceValues[i].toString() + ",\n";
			}
			if(sequenceValues.length > 0){
				retval += sequenceValues[sequenceValues.length-1].toString();
			}
		}
		retval += "]";
		return retval;
	}
}
