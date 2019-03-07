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
 * This structure represents the Service Specific Permissions (SSP) relevant to a given entry in a PsidSsp. The
 * meaning of the SSP is specific to the associated Psid. SSPs may be PSID-specific octet strings or bitmapbased.
 * See Annex C for further discussion of how application specifiers may choose which SSP form to
 * use.
 * <p>
 *     <b>Consistency with issuing certificate.</b>If a certificate has an appPermissions entry A for which the ssp
 *     field is opaque, A is consistent with the issuing certificate if the issuing certificate contains one of the
 *     following:
 *     <ul>
 *         <li>(OPTION 1) A SubjectPermissions field indicating the choice all and no PsidSspRange field
 * containing the psid field in A;</li>
 *         <li>(OPTION 2) A PsidSspRange P for which the following holds:
 *         <ul>
 *             <li>The psid field in P is equal to the psid field in A and one of the following is true:
 *             <ul>
 *                 <li>The sspRange field in P indicates all.</li>
 *                 <li>The sspRange field in P indicates opaque and one of the entries in the opaque field
 * in P is an OCTET STRING identical to the opaque field in A.</li>
 *             </ul>
 *             </li>
 *         </ul>
 *         </li>
 *     </ul>
 * </p>
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ServiceSpecificPermissions extends COERChoice {
	
	private static final long serialVersionUID = 1L;
	
	public enum ServiceSpecificPermissionsChoices implements COERChoiceEnumeration{
		opaque,
		bitmapSsp;


		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			if(this == bitmapSsp){
				return new BitmapSsp();
			}
			return new COEROctetStream(0, null);
		}

		/**
		 * @return always false, no extension exists.
		 */
		@Override
		public boolean isExtension() {
			return this == bitmapSsp;
		}
	}
	
	/**
	 * Constructor used when encoding of type opaque.
	 */
	public ServiceSpecificPermissions(ServiceSpecificPermissionsChoices choice, byte[] value) throws IOException {
		super(choice, new COEROctetStream(value,0, null) );
	}

	/**
	 * Constructor used when encoding of type bitmapSsp.
	 */
	public ServiceSpecificPermissions(ServiceSpecificPermissionsChoices choice, BitmapSsp bitmapSsp) throws IOException {
		super(choice, bitmapSsp);
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

	/**
	 *
	 * @return returns the bitmapSsp if type is bitmapSsp, otherwise null.
	 */
	public BitmapSsp getBitmapSsp(){
		if(getType() == ServiceSpecificPermissionsChoices.bitmapSsp){
			return (BitmapSsp) getValue();
		}
		return null;
	}
	

	@Override
	public String toString() {
		if(choice == ServiceSpecificPermissionsChoices.opaque) {
			return "ServiceSpecificPermissions [" + choice + "=[" + new String(Hex.encode(getData())) + "]]";
		}
		return "ServiceSpecificPermissions [" + choice + "=[" + getBitmapSsp().toString().replace("BitmapSsp ","") + "]]";
	}
	
}
