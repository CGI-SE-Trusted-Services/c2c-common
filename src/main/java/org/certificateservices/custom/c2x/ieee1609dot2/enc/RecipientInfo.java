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

/**
 *  This data structure is used to transfer the data encryption key to an individual recipient of an
 *  EncryptedData. The option pskRecipInfo is selected if the EncryptedData was encrypted using the
 *  static encryption key approach specified in 5.3.4.2. The other options are selected if the EncryptedData was
 *  encrypted using the ephemeral encryption key approach specified in 5.3.4.1. The meanings of the choices are:
 *  
 *  <li>pskRecipInfo: The ciphertext was encrypted directly using a symmetric key.
 *  <li>symmRecipInfo: The data encryption key was encrypted using a symmetric key.
 *  <li>certRecipInfo: The data encryption key was encrypted using the public encryption key in a certificate. This field contains the HashedId8 of the certificate. In this case, the parameter P1 to ECIES as defined in 5.3.5 is the hash of the certificate.
 *  <li>signedDataRecipInfo: The data encryption key was encrypted using the public response encryption key from a SignedData. In this case, this field contains the HashedId8 of the1609Dot2Data containing the SignedData containing the encryption key. In this case, the parameter P1 to ECIES as defined in 5.3.5 is the SHA-256 hash of the Ieee1609Dot2Data containing the response encryption key.
 *  <li>rekRecipInfo: The data encryption key was encrypted using a public response encryption key that was not obtained from a SignedData. In this case, this field contains the HashedId8 of the response encryption key. In this case, the parameter P1 to ECIES as defined in 5.3.5 is the hash of the empty string.
 *  <p>
 *  <b>NOTE</b>The rekRecipInfo should only be used if the SignedData is not available as it potentially allows
 *  misbinding attacks: it is included in these structures specifically to enable certificate response encryption from a PCA
 *  to an end-entity device.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class RecipientInfo extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum RecipientInfoChoices implements COERChoiceEnumeration{
		pskRecipInfo,
		symmRecipInfo,
		certRecipInfo,
		signedDataRecipInfo,
		rekRecipInfo;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			switch (this) {
			case pskRecipInfo:
				return new PreSharedKeyRecipientInfo();
			case symmRecipInfo:
				return new SymmRecipientInfo();
			default:
				return new PKRecipientInfo();
			}
		}
	}
	
	/**
	 * Constructor used when encoding of type pskRecipInfo
	 */
	public RecipientInfo(PreSharedKeyRecipientInfo keyInfo) throws IllegalArgumentException{
		super(RecipientInfoChoices.pskRecipInfo, keyInfo);
	}
	
	/**
	 * Constructor used when encoding of type symmRecipInfo
	 */
	public RecipientInfo(SymmRecipientInfo keyInfo) throws IllegalArgumentException{
		super(RecipientInfoChoices.symmRecipInfo, keyInfo);
	}
	
	/**
	 * Constructor used when encoding of types certRecipInfo, signedDataRecipInfo, rekRecipInfo
	 */
	public RecipientInfo(RecipientInfoChoices type, PKRecipientInfo keyInfo) throws IllegalArgumentException{
		super(type, keyInfo);
	}
	

	/**
	 * Constructor used when decoding.
	 */
	public RecipientInfo() {
		super(RecipientInfoChoices.class);
	}
		
	/**
	 * Returns the type of key id.
	 */
	public RecipientInfoChoices getType(){
		return (RecipientInfoChoices) choice;
	}

	@Override
	public String toString() {
		return "RecipientInfo [" + choice + "=" + value.toString().replace("PreSharedKeyRecipientInfo ", "").replace("SymmRecipientInfo ", "").replace("PKRecipientInfo ", "") +"]";
	}
	
}
