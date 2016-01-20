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
package org.certificateservices.custom.c2x.ieee1609dot2.enc;

import java.io.IOException;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EciesP256EncryptedKey;

/**
 * This data structure contains an encrypted data encryption key.
 * <p>
 * <b>Critical information fields:</b> If present, this is a critical information field as defined in 5.2.5. 
 * An implementation that does not recognize the indicated enumerated value for this type in an encrypted SPDU shall 
 * reject the SPDU as invalid.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EncryptedDataEncryptionKey extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum EncryptedDataEncryptionKeyChoices implements COERChoiceEnumeration{
		eciesNistP256,
		eciesBrainpoolP256r1;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
	      return new EciesP256EncryptedKey();
		}
	}
	
	/**
	 * Constructor used when encoding of type aes128ccm
	 */
	public EncryptedDataEncryptionKey(EncryptedDataEncryptionKeyChoices type, EciesP256EncryptedKey key) throws IllegalArgumentException{
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
