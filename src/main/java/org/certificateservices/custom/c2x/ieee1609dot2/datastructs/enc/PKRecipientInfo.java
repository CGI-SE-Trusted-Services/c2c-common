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

/**
 *<li>recipientId contains the hash of the container for the encryption public key as specified in the definition of RecipientInfo.
 *<li>encKey contains the encrypted key.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PKRecipientInfo extends COERSequence {
	

	private static final long serialVersionUID = 1L;
	
	private static final int RECIPIENTID = 0;
	private static final int ENCKEY = 1;

	/**
	 * Constructor used when decoding
	 */
	public PKRecipientInfo(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public PKRecipientInfo(HashedId8 recipientId, EncryptedDataEncryptionKey encKey){
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
	public EncryptedDataEncryptionKey getEncKey(){
		return (EncryptedDataEncryptionKey) get(ENCKEY);
	}
	

	
	private void init(){
		addField(RECIPIENTID, false, new HashedId8(), null);
		addField(ENCKEY, false, new EncryptedDataEncryptionKey(), null);
	}
	
	@Override
	public String toString() {
		return "PKRecipientInfo [recipientId=" + getRecipientId().toString().replace("HashedId8 ", "") + ", encKey=" + getEncKey().toString().replace("EncryptedDataEncryptionKey ", "") + "]";
	}
	
}
