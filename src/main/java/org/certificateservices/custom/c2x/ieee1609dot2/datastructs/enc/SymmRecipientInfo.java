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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;

import java.io.IOException;

/**
 * <li>recipientId contains the hash of the symmetric key encryption key that may be used to decrypt
 * the data encryption key. It consists of the low-order 8 bytes of the SHA-256 hash of the COER
 * encoding of a SymmetricEncryptionKey structure containing the symmetric key in question. The symmetric key may be
 * established by any appropriate means agreed by the two parties to the exchange.
 * <li>encKey contains the encrypted data encryption key within an AES-CCM ciphertext.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SymmRecipientInfo extends COERSequence {
	

	private static final long serialVersionUID = 1L;
	
	private static final int RECIPIENTID = 0;
	private static final int ENCKEY = 1;

	/**
	 * Constructor used when decoding
	 */
	public SymmRecipientInfo(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SymmRecipientInfo(HashedId8 recipientId, SymmetricCiphertext encKey) throws IOException {
		super(false,2);
		init();
		set(RECIPIENTID, recipientId);
		set(ENCKEY, encKey);
	
	}

	/**
	 * 
	 * @return recipientId
	 */
	public HashedId8 getRecipientId(){
		return (HashedId8) get(RECIPIENTID);
	}
	
	/**
	 * 
	 * @return encKey
	 */
	public SymmetricCiphertext getEncKey(){
		return (SymmetricCiphertext) get(ENCKEY);
	}
	

	
	private void init(){
		addField(RECIPIENTID, false, new HashedId8(), null);
		addField(ENCKEY, false, new SymmetricCiphertext(), null);
	}
	
	@Override
	public String toString() {
		return "SymmRecipientInfo [recipientId=" + getRecipientId().toString().replace("HashedId8 ", "") + ", encKey=" + getEncKey().toString().replace("SymmetricCiphertext ", "") + "]";
	}
	
}
