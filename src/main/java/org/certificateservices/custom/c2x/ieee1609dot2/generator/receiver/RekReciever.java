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
package org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PKRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;

/**
 * PublicKey Receiver used for public keys not associated with any certificate or SignedData. Should be used with caution.
 * <p>
 * See section 5.3.5 in IEEE 1609.2
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public class RekReciever extends BasePKReceiver {

	private PublicKey publicKey;

	public RekReciever(PrivateKey privateKey, PublicKey publicKey){
		super(privateKey);
		this.publicKey = publicKey;
	}

	@Override
	public SecretKey extractDecryptionKey(
			Ieee1609Dot2CryptoManager cryptoManager, RecipientInfo recipientInfo)
			throws IllegalArgumentException, GeneralSecurityException,
			IOException {
		PKRecipientInfo pkRecInfo = (PKRecipientInfo) recipientInfo.getValue();
		return cryptoManager.ieeeECEISDecryptSymmetricKey(pkRecInfo.getEncKey(), privateKey, pkRecInfo.getEncKey().getType(), null);
	}

	@Override
	protected byte[] getReferenceData() throws IOException {
		return publicKey.getEncoded();
	}

}
