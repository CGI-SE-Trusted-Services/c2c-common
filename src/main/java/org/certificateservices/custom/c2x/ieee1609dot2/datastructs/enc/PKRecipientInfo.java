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
 * <ul>
 *<li>recipientId contains the hash of the "container" for the encryption public key as specified in
 * the definition of RecipientInfo. Specifically, depending on the choice indicated by the containing
 * RecipientInfo structure:
 * <br>
 *     ⎯ If the containing RecipientInfo structure indicates certRecipInfo, this field
 * contains the HashedId8 of the certificate. The HashedId8 is calculated with the wholecertificate
 * hash algorithm, determined as described in 6.4.3.
 * <br>
 * ⎯ If the containing RecipientInfo structure indicates signedDataRecipInfo, this
 * field contains the HashedId8 of the Ieee1609Dot2Data of type signed that contained the
 * encryption key, with that Ieee1609Dot2Data canonicalized per 6.3.4. The HashedId8 is
 * calculated with SHA-256.
 * <br>
 * ⎯ If the containing RecipientInfo structure indicates rekRecipInfo, this field contains
 * the HashedId8 of the COER encoding of a PublicEncryptionKey structure containing the
 * response encryption key. The HashedId8 is calculated with SHA-256.
 *<li>encKey contains the encrypted key.</li>
 * </ul>
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
	public PKRecipientInfo(HashedId8 recipientId, EncryptedDataEncryptionKey encKey) throws IOException {
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
