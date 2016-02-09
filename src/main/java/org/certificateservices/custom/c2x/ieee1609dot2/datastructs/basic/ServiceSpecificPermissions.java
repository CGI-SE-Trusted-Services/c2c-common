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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic;

import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;

/**
 * This structure represents the Service Specific Permissions (SSP) relevant to a given entry in a PsidSsp. 
 * The meaning of the SSP is specific to the associated Psid. 
 * 
 * <b>Critical information fields:</b>
 * If present, this is a critical information field as defined in 5.2.5. An implementation that does not recognize 
 * the indicated CHOICE when verifying a signed SPDU shall indicate that the signed SPDU is invalid.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ServiceSpecificPermissions extends COERChoice {
	
	private static final long serialVersionUID = 1L;
	
	public enum ServiceSpecificPermissionsChoices implements COERChoiceEnumeration{
		opaque();

	
		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			return new COEROctetStream(0, null);
		}
	}
	
	/**
	 * Constructor used when encoding.
	 */
	public ServiceSpecificPermissions(ServiceSpecificPermissionsChoices choice, byte[] value) {
		super(choice, new COEROctetStream(value,0, null) );
	}

	/**
	 * Constructor used when decoding.
	 */
	public ServiceSpecificPermissions() {
		super(ServiceSpecificPermissionsChoices.class);
	}

	
	/**
	 * Returns type of identified region, one of ServiceSpecificPermissionsChoices enumeration.
	 */
	public ServiceSpecificPermissionsChoices getType(){
		return (ServiceSpecificPermissionsChoices) choice;
	}
	
	/**
	 * Returns the data if type is opaque, otherwise null.
	 */
	public byte[] getData(){
		if(getType() == ServiceSpecificPermissionsChoices.opaque){
			return ((COEROctetStream) getValue()).getData();
		}
		return null;
	}
	

	@Override
	public String toString() {
		return "ServiceSpecificPermissions [" + choice + "=[" + new String(Hex.encode(getData())) + "]]";
	}
	
}
