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

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

import java.io.IOException;

/**
 * This data structure encodes data that has been encrypted to one or more recipients using the recipients’ public or symmetric keys as specified in 5.3.4.
 * <p>
 * The type contains the following fields:
 * <li>recipients contains one or more RecipientInfos, defined below. If the ciphertext was produced using the static data encryption
 * key approach specified in 5.3.4.2, recipients contains a single entry of type PreSharedKeyRecipientInfo. If the ciphertext
 * was produced using the ephemeral data encryption key approach specified in 5.3.4.1, recipients contains one or more
 * entries which are of any type other than PreSharedKeyRecipientInfo.</li>
 * <li>ciphertext contains the encrypted data. This is the encryption of an encoded Ieee1609Dot2 Data structure.</li>
 * </p>
 * <p>
 *     <b>Critical information fields:</b>If present, recipients is a critical information field as defined in 5.2.5. An implementation that
 * does not support the number of RecipientInfo in recipients when decrypted shall indicate that
 * the encrypted SPDU could not be decrypted due to unsupported critical information fields. A
 * compliant implementation shall support recipients fields containing at least eight entries.
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EncryptedData extends COERSequence {
	

	private static final long serialVersionUID = 1L;
	
	private static final int RECIPIENTS = 0;
	private static final int CIPHERTEXT = 1;

	/**
	 * Constructor used when decoding
	 */
	public EncryptedData(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public EncryptedData(SequenceOfRecipientInfo recipients, SymmetricCiphertext ciphertext) throws IOException {
		super(false,2);
		init();

		set(RECIPIENTS, recipients);
		set(CIPHERTEXT, ciphertext);
	
	}

	/**
	 * 
	 * @return recipients
	 */
	public SequenceOfRecipientInfo getRecipients(){
		return (SequenceOfRecipientInfo) get(RECIPIENTS);
	}
	
	/**
	 * 
	 * @return ciphertext
	 */
	public SymmetricCiphertext getCipherText(){
		return (SymmetricCiphertext) get(CIPHERTEXT);
	}
	

	
	private void init(){
		addField(RECIPIENTS, false, new SequenceOfRecipientInfo(), null);
		addField(CIPHERTEXT, false, new SymmetricCiphertext(), null);
	}
	
	@Override
	public String toString() {
		return "EncryptedData [\n" +
	   "  recipients=" + getRecipients().toString().replace("SequenceOfRecipientInfo ", "") + ",\n" +
	   "  ciphertext=" + getCipherText().toString().replace("SymmetricCiphertext ", "") + "\n]";
	}
	
}
