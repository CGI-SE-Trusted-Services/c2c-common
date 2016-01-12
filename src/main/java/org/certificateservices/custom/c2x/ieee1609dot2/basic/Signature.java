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
 * This structure represents a signature for a supported public key algorithm. 
 * It may be contained within one of a number of data structures: SignedData, Certificate.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Signature extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum SignatureChoices implements COERChoiceEnumeration{
		ecdsaNistP256Signature,
		ecdsaBrainpoolP256r1Signature;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			return new EcdsaP256Signature();
		}
	}
	
	/**
	 * Constructor used when encoding.
	 */
	public Signature(SignatureChoices choice, EcdsaP256Signature value) {
		super(choice, value);
	}


	/**
	 * Constructor used when decoding.
	 */
	public Signature() {
		super(SignatureChoices.class);
	}
		
	/**
	 * Returns the type of signature.
	 */
	public SignatureChoices getType(){
		return (SignatureChoices) choice;
	}

	@Override
	public String toString() {
		return "Signature [" + choice + "=" +  value + "]";
	}
	
}
