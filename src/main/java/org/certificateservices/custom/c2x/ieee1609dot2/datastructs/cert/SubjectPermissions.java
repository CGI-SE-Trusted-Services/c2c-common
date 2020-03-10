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

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COERNull;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange;

/**
 * This indicates the PSIDs and associated SSPs for which certificate issuance or request permissions are granted by a PsidGroupPermissions structure. 
 * If this takes the value explicit, the enclosing PsidGroupPermissions structure grants certificate issuance or request permissions for the indicated 
 * PSIDs and SSP ranges. If this takes the value all, the enclosing PsidGroupPermissions structure grants certificate issuance or request permissions 
 * for all PSIDs not indicated by other PsidGroupPermissions in the same certIssuePermissions or certRequestPermissions field.
 * <p>
 * <b>Critical information fields:</b>
 * <li>If present, this is a critical information field as defined in 5.2.5. An implementation that does not recognize the indicated CHOICE when verifying 
 * a signed SPDU shall indicate that the signed SPDU is invalid.
 * <li>If present, explicit is a critical information field as defined in 5.2.5. An implementation that does not support the number of PsidSspRange in explicit 
 * when verifying a signed SPDU shall indicate that the signed SPDU is invalid. A compliant implementation shall support explicit fields 
 * containing at least eight entries.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SubjectPermissions extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum SubjectPermissionsChoices implements COERChoiceEnumeration{
		explicit,
		all;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			if(this == explicit){
				return new SequenceOfPsidSspRange();
			}
			return new COERNull();
		}

		/**
		 * @return always false, no extension exists.
		 */
		@Override
		public boolean isExtension() {
			return false;
		}
	}
	
	/**
	 * Constructor used when encoding.
	 * @param choice the type of SubjectPermissions
	 * @param value set if type is explicit otherwise null.
	 */
	public SubjectPermissions(SubjectPermissionsChoices choice, SequenceOfPsidSspRange value) {
		super(choice, (value!= null ? value : new COERNull()));
	}
	

	/**
	 * Constructor used when decoding.
	 */
	public SubjectPermissions() {
		super(SubjectPermissionsChoices.class);
	}
		
	/**
	 * Returns the type of key.
	 */
	public SubjectPermissionsChoices getType(){
		return (SubjectPermissionsChoices) choice;
	}

	@Override
	public String toString() {
		if(choice == SubjectPermissionsChoices.all){
			return "SubjectPermissions [" + choice +"]";
		}
		return "SubjectPermissions [" + choice + "=" +  value.toString().replace("SequenceOfPsidSspRange ", "") + "]";
	}
	
}
