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

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;

/**
 * This structure specifies the bytes of a public encryption key for a particular algorithm. The only algorithm
 * supported is ECIES over either the NIST P256 or the Brainpool P256r1 curve as specified in 5.3.5.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class BasePublicEncryptionKey extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum BasePublicEncryptionKeyChoices implements COERChoiceEnumeration, AlgorithmIndicator{
		ecdsaNistP256,
		ecdsaBrainpoolP256r1;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			return new EccP256CurvePoint();
		}
		
		@Override
		public Algorithm getAlgorithm() {
			switch (this) {
			case ecdsaNistP256:
				return new Algorithm(Algorithm.Symmetric.aes128Ccm,Algorithm.Signature.ecdsaNistP256, Algorithm.Encryption.ecies,Algorithm.Hash.sha256);
			case ecdsaBrainpoolP256r1:
			default:
				return new Algorithm(Algorithm.Symmetric.aes128Ccm,Algorithm.Signature.ecdsaBrainpoolP256r1, Algorithm.Encryption.ecies,Algorithm.Hash.sha256);
			}	
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
	 */
	public BasePublicEncryptionKey(BasePublicEncryptionKeyChoices choice, COEREncodable value) throws IOException{
		super(choice, value);
		if(!(value instanceof EccP256CurvePoint)){
			throw new IOException("Invalid BasePublicEncryptionKey value, must be a EccP256CurvePoint.");
		}
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
