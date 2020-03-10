/************************************************************************
 *                                                                       *
3 *  Certificate Service -  Car2Car Core                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc;

import java.io.IOException;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;

/**
 * This data structure encapsulates a ciphertext generated with an approved symmetric algorithm.
 * <p>
 * <b>Critical information fields:</b> If present, this is a critical information field as defined in 5.2.5. An implementation that does not 
 * recognize the indicated CHOICE value for this type in an encrypted SPDU shall reject the SPDU as invalid.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SymmetricCiphertext extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum SymmetricCiphertextChoices implements COERChoiceEnumeration, AlgorithmIndicator{
		aes128ccm;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
	      return new AesCcmCiphertext();
		}
		
		@Override
		public Algorithm getAlgorithm() {
			return new Algorithm(Algorithm.Symmetric.aes128Ccm, null, null, null);
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
	 * Constructor used when encoding of type aes128ccm
	 */
	public SymmetricCiphertext(AesCcmCiphertext cipherText) {
		super(SymmetricCiphertextChoices.aes128ccm, cipherText);
	}
	

	/**
	 * Constructor used when decoding.
	 */
	public SymmetricCiphertext() {
		super(SymmetricCiphertextChoices.class);
	}
		
	/**
	 * Returns the type of id.
	 */
	public SymmetricCiphertextChoices getType(){
		return (SymmetricCiphertextChoices) choice;
	}

	@Override
	public String toString() {
		return "SymmetricCiphertext [" + choice + "=" + value.toString().replace("AesCcmCiphertext ", "") +"]";
	}
	
}
