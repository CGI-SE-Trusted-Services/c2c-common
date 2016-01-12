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

/**
 * This structure specifies the bytes of a public encryption key for a particular algorithm. The only algorithm
 * supported is ECIES over either the NIST P256 or the Brainpool P256r1 curve as specified in 5.3.5.
 * <p>
 * <b>Critical Information Fields</b>If present, this is a critical information field as defined in 5.2.5. An
 * implementation that does not recognize the indicated CHOICE for this type when verifying a signed SPDU
 * shall indicate that the signed SPDU is invalid.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class BasePublicEncryptionKey extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum BasePublicEncryptionKeyChoices implements COERChoiceEnumeration{
		ecdsaNistP256,
		ecdsaBrainpoolP256r1;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			return new EccP256CurvePoint();
		}
	}
	
	/**
	 * Constructor used when encoding.
	 */
	public BasePublicEncryptionKey(BasePublicEncryptionKeyChoices choice, EccP256CurvePoint value) throws IllegalArgumentException{
		super(choice, value);
	}


	/**
	 * Constructor used when decoding.
	 */
	public BasePublicEncryptionKey() {
		super(BasePublicEncryptionKeyChoices.class);
	}
		
	/**
	 * Returns the type of key.
	 */
	public BasePublicEncryptionKeyChoices getType(){
		return (BasePublicEncryptionKeyChoices) choice;
	}

	@Override
	public String toString() {
		return "BasePublicEncryptionKey [" + choice + "=" +  value.toString().replace("EccP256CurvePoint ", "") + "]";
	}
	
}
