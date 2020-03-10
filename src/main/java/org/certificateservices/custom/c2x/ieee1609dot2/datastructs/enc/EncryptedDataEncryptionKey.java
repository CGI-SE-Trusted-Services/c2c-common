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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc;

import java.io.IOException;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EciesP256EncryptedKey;

/**
 * This data structure contains an encrypted data encryption key.
 * <p>
 * <b>Critical information fields:</b> If present, this is a critical information field as defined in 5.2.5. 
 * If an implementation receives an encrypted SPDU and determines that one or more RecipientInfo fields are relevant to
 * it, and if all of those RecipientInfos contain an EncryptedDataEncryptionKey such that the implementation does not
 * recognize the indicated CHOICE, the implementation shall indicate that the encrypted SPDU is not decryptable.
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EncryptedDataEncryptionKey extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum EncryptedDataEncryptionKeyChoices implements COERChoiceEnumeration, AlgorithmIndicator{
		eciesNistP256,
		eciesBrainpoolP256r1;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
	      return new EciesP256EncryptedKey();
		}

		/**
		 * @return no extensions exists for enumeration
		 */
		@Override
		public boolean isExtension() {
			return false;
		}

		public int getVLength(){
			switch(this){
			case eciesNistP256:
			case eciesBrainpoolP256r1:
			default:
				return 33;
			}
		}
		
		public int getOutputTagLength(){
			switch(this){
			case eciesNistP256:
			case eciesBrainpoolP256r1:
			default:
				return 16;
			}
		}

		@Override
		public Algorithm getAlgorithm() {
			switch (this) {
			case eciesNistP256:
				return new Algorithm(Algorithm.Symmetric.aes128Ccm,Algorithm.Signature.ecdsaNistP256, Algorithm.Encryption.ecies,Algorithm.Hash.sha256);
			case eciesBrainpoolP256r1:
			default:
				return new Algorithm(Algorithm.Symmetric.aes128Ccm,Algorithm.Signature.ecdsaBrainpoolP256r1, Algorithm.Encryption.ecies,Algorithm.Hash.sha256);
			}	
		}

	}
	
	/**
	 * Constructor used when encoding of type aes128ccm
	 */
	public EncryptedDataEncryptionKey(EncryptedDataEncryptionKeyChoices type, EciesP256EncryptedKey key) {
		super(type, key);
	}
	

	/**
	 * Constructor used when decoding.
	 */
	public EncryptedDataEncryptionKey() {
		super(EncryptedDataEncryptionKeyChoices.class);
	}
		
	/**
	 * Returns the type of id.
	 */
	public EncryptedDataEncryptionKeyChoices getType(){
		return (EncryptedDataEncryptionKeyChoices) choice;
	}

	@Override
	public String toString() {
		return "EncryptedDataEncryptionKey [" + choice + "=" + value.toString().replace("EciesP256EncryptedKey ", "") +"]";
	}
	
}
