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

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PKRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData;

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
			throws BadArgumentException, GeneralSecurityException{
		PKRecipientInfo pkRecInfo = (PKRecipientInfo) recipientInfo.getValue();
		byte[] p1Hash = cryptoManager.digest(new byte[0], EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices.eciesNistP256); // Always use hash 256
		return cryptoManager.ieeeEceisDecryptSymmetricKey2017(pkRecInfo.getEncKey(), privateKey, p1Hash);
	}

	@Override
	protected byte[] getReferenceData() throws IOException {
		return publicKey.getEncoded();
	}

	@Override
	public AlgorithmIndicator getHashAlgorithm() {
		return HashAlgorithm.sha256; // Always use hash 256
	}

}
