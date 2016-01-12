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
package org.certificateservices.custom.c2x.ieee1609dot2.basic;

import java.io.IOException;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COERNull;

/**
 * This structure identifies the SSPs associated with a PSID for which the holder may issue or request certificates.
 * <p>
 * The contents of this field depend on whether the certificate is an implicit or an explicit certificate.
 * <li>If the choice indiated is opaque, the certificate holder may issue or request certificates with the listed SSPs for that PSID.
 * <li>If the choice indicated is all, the holder may issue or request certificates for the any SSP for that PSID.
 * <p>
 * An SSP associated with a given PSID in a subordinate certificate is consistent with the SspRange associated with that PSID in the 
 * issuing certificate if one of the following hold:
 * <li>The issuing certificate SspRange is of type opaque and one of the entries in the range exactly matches the SSP in the subordinate certificate
 * <li>The issuing certificate SspRange is of type all.
 * <p>
 * An SspRange associated with a given PSID in a subordinate certificate is consistent with the SspRange 
 * associated with that PSID in an issuing certificate if one of the following hold:
 * <li>The issuing certificate SspRange is of type opaque and all of the entries in the subordinate
 * certificate’s SspRange exactly match an entry in the issuing certificate’s SspRange.   
 * <li>The issuing certificate SspRange is of type all.
 * 
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SspRange extends COERChoice {
	
	private static final long serialVersionUID = 1L;
	
	public enum SspRangeChoices implements COERChoiceEnumeration{
		opaque,
		all;

	
		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			if(this == opaque){
				return new SequenceOfOctetString();
			}
			return new COERNull();
		}
	}
	
	/**
	 * Constructor used when encoding
	 * @param choice type of SspRange
	 * @param data SequenceOfOctetString used if type is opaque, otherwise use null.
	 */
	public SspRange(SspRangeChoices choice, SequenceOfOctetString data) {
		super(choice, (choice == SspRangeChoices.opaque ? data : new COERNull()));
	}

	/**
	 * Constructor used when decoding.
	 */
	public SspRange() {
		super(SspRangeChoices.class);
	}

	
	/**
	 * Returns type of identified region, one of SspRangeChoices enumeration.
	 */
	public SspRangeChoices getType(){
		return (SspRangeChoices) choice;
	}
	
	/**
	 * Returns the data if type is opaque, otherwise null.
	 */
	public SequenceOfOctetString getOpaqueData(){
		if(getType() == SspRangeChoices.opaque){
			return ((SequenceOfOctetString) getValue());
		}
		return null;
	}
	

	@Override
	public String toString() {
		if(choice == SspRangeChoices.opaque){
			return "SspRange [" + choice + "=[" + getValue().toString().replaceAll("SequenceOfOctetString ", "") + "]]";	
		}
		return "SspRange [" + choice + "]";
	}
	
}
