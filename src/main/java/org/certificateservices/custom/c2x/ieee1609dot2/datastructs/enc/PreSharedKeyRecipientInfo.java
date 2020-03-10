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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;

import java.io.IOException;

/**
 * This data structure is used to indicate a symmetric key that may be used directly to decrypt a
 * SymmetricCiphertext. It consists of the low-order 8 bytes of the SHA-256 hash of the COER encoding of a
 * SymmetricEncryptionKey structure containing the symmetric key in question. The symmetric key may be
 * established by any appropriate means agreed by the two parties to the exchange.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PreSharedKeyRecipientInfo extends HashedId8 {
	

	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public PreSharedKeyRecipientInfo(){
	}
	
	/**
	 * Constructor used when encoding
	 */
	public PreSharedKeyRecipientInfo(byte[] recipientInfo) throws IOException {
		super(recipientInfo);
	}
	
	@Override
	public String toString() {
		return "PreSharedKeyRecipientInfo [" + new String(Hex.encode(getHashedId())) + "]";
	}
	
}
