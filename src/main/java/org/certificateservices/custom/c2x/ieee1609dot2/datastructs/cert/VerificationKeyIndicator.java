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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccCurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP384CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey;

/**
 * This structure represents a public key and states with what algorithm the public key is to be used. Cryptographic mechanisms are defined in 5.3.
 * <p>
 * An EccP256CurvePoint within a PublicVerificationKey structure is invalid if it indicates the choice x- only.
 * </p>
 * <p>Critical information fields: If present, this is a critical information field as defined in 5.2.5. An
 * implementation that does not recognize the indicated CHOICE for this type when verifying a signed SPDU
 * shall indicate that the signed SPDU is invalid.</p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class VerificationKeyIndicator extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum VerificationKeyIndicatorChoices implements COERChoiceEnumeration{
		verificationKey,
		reconstructionValue;

		@Override
		public COEREncodable getEmptyCOEREncodable()  {
			if(this == verificationKey){
				return new PublicVerificationKey();
			}
			return new EccP256CurvePoint();
		}

		/**
		 * @return always false, no extension choice exists.
		 */
		@Override
		public boolean isExtension() {
			return false;
		}
	}
	
	/**
	 * Constructor used when encoding of type verificationKey
	 */
	public VerificationKeyIndicator(PublicVerificationKey value) {
		super(VerificationKeyIndicatorChoices.verificationKey, value);
	}
	
	/**
	 * Constructor used when encoding of type reconstructionValue
	 */
	public VerificationKeyIndicator(EccCurvePoint value) {
		super(VerificationKeyIndicatorChoices.reconstructionValue, value);
	}

	/**
	 * Constructor used when decoding.
	 */
	public VerificationKeyIndicator() {
		super(VerificationKeyIndicatorChoices.class);
	}
		
	/**
	 * Returns the type of key.
	 */
	public VerificationKeyIndicatorChoices getType(){
		return (VerificationKeyIndicatorChoices) choice;
	}

	@Override
	public String toString() {
		return "VerificationKeyIndicator [" + choice + "=" +  value.toString().replace("EccP256CurvePoint ", "").replace("PublicVerificationKey ", "") + "]";
	}
	
}
