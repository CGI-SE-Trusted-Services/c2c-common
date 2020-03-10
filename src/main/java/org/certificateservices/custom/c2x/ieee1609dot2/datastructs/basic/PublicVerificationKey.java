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
import org.certificateservices.custom.c2x.common.crypto.Algorithm.Hash;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;

/**
 * This structure represents a public key and states with what algorithm the public key is to be used. Cryptographic mechanisms are defined in 5.3.
 * <p>
 * An EccP256CurvePoint within a PublicVerificationKey structure is invalid if it indicates the choice x- only.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PublicVerificationKey extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum PublicVerificationKeyChoices implements COERChoiceEnumeration, AlgorithmIndicator{
		ecdsaNistP256,
		ecdsaBrainpoolP256r1,
		ecdsaBrainpoolP384r1;


		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			if(this == ecdsaBrainpoolP384r1){
				return new EccP384CurvePoint();
			}
			return new EccP256CurvePoint();
		}

		@Override
		public Algorithm getAlgorithm() {
			switch (this) {
			case ecdsaNistP256:
				return new Algorithm(null,Algorithm.Signature.ecdsaNistP256, null,Hash.sha256);
			case ecdsaBrainpoolP256r1:
				return new Algorithm(null,Algorithm.Signature.ecdsaBrainpoolP256r1, null,Hash.sha256);
				case ecdsaBrainpoolP384r1:
			default:
				return new Algorithm(null,Algorithm.Signature.ecdsaBrainpoolP384r1, null,Hash.sha384);
			}	
		}

		/**
		 * @return true for ecdsaBrainpoolP384r1.
		 */
		@Override
		public boolean isExtension() {
			return this == ecdsaBrainpoolP384r1;
		}
	}

	/**
	 * General Constructor used when encoding.
	 */
	public PublicVerificationKey(PublicVerificationKeyChoices choice, COERChoice value) throws IOException{
		super(choice, value);
		if(value instanceof EccP384CurvePoint){
			if(choice != PublicVerificationKeyChoices.ecdsaBrainpoolP384r1){
				throw new IOException("EccP384CurvePoint is not supported for PublicVerificationKey with type " + choice + ".");
			}
			if(((EccP384CurvePoint) value).getType() == EccP384CurvePoint.EccP384CurvePointChoices.xonly){
				throw new IOException("EccP384CurvePoint of type xonly is invalid for structure PublicVerificationKey");
			}
		}else{
			if(value instanceof EccP256CurvePoint){
				if(choice == PublicVerificationKeyChoices.ecdsaBrainpoolP384r1){
					throw new IOException("EccP256CurvePoint is not supported for PublicVerificationKey with type " + choice + ".");
				}
				if(((EccP256CurvePoint) value).getType() == EccP256CurvePointChoices.xonly){
					throw new IOException("EccP256CurvePoint of type xonly is invalid for structure PublicVerificationKey");
				}
			}else{
				throw new IOException("Invalid value to PublicVerificationKey, must be either EccP384CurvePoint or EccP256CurvePoint, not " + value.getClass().getSimpleName());
			}
		}
	}

	/**
	 * Constructor used when decoding.
	 */
	public PublicVerificationKey() {
		super(PublicVerificationKeyChoices.class);
	}
		
	/**
	 * Returns the type of key.
	 */
	public PublicVerificationKeyChoices getType(){
		return (PublicVerificationKeyChoices) choice;
	}

	@Override
	public String toString() {
		return "PublicVerificationKey [" + choice + "=" +  value.toString().replace("EccP256CurvePoint ", "") + "]";
	}
	
}
