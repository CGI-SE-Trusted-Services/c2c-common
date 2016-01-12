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
 * This structure contains an encryption key, which may be a public or a symmetric key.
 * <p>
 * Values depending on type either:
 * <li>PublicEncryptionKey
 * <li>SymmetricEncryptionKey
 * 
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EncryptionKey extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum EncryptionKeyChoices implements COERChoiceEnumeration{
		public_,
		symmetric;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			if(this == public_){
				return new PublicEncryptionKey();
			}
			return new SymmetricEncryptionKey();
		}
	}
	
	/**
	 * Constructor used when encoding public key.
	 */
	public EncryptionKey(PublicEncryptionKey publicKey) throws IllegalArgumentException{
		super(EncryptionKeyChoices.public_, publicKey);
	}
	
	/**
	 * Constructor used when encoding symmetric key.
	 */
	public EncryptionKey(SymmetricEncryptionKey symmetricKey) throws IllegalArgumentException{
		super(EncryptionKeyChoices.symmetric, symmetricKey);
	}
	
	/**
	 * Constructor used when decoding
	 */
	public EncryptionKey() throws IllegalArgumentException{
		super(EncryptionKeyChoices.class);
	}

		
	/**
	 * Returns the type of key.
	 */
	public EncryptionKeyChoices getType(){
		return (EncryptionKeyChoices) choice;
	}

	@Override
	public String toString() {
		return "EncryptionKey [" + choice + "=" +  value.toString().replace("PublicEncryptionKey ", "").replace("SymmetricEncryptionKey ", "") + "]";
	}
	
}
