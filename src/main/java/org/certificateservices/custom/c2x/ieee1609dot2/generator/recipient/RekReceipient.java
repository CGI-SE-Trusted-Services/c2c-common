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
package org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PKRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo.RecipientInfoChoices;

/**
 * PublicKey Receipient used for public keys not associated with any certificate or SignedData. Should be used with caution.
 * <p>
 * See section 5.3.5 in IEEE 1609.2
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public class RekReceipient extends BasePKRecipient{

	private PublicKey publicKey;
	
	public RekReceipient(PublicKey publicKey){
		this.publicKey = publicKey;
	}
	
	@Override
	public RecipientInfo toRecipientInfo(AlgorithmIndicator alg,
			Ieee1609Dot2CryptoManager cryptoManager, SecretKey encryptionKey)
			throws BadArgumentException, GeneralSecurityException, IOException {
		
		byte[] keyHash = cryptoManager.digest(publicKey.getEncoded(), HashAlgorithm.sha256);
		byte[] p1Hash = cryptoManager.digest(new byte[0], HashAlgorithm.sha256);
		EncryptedDataEncryptionKey encKey = cryptoManager.ieeeEceisEncryptSymmetricKey2017(getEncKeyType(alg), publicKey, encryptionKey, p1Hash);
		
		PKRecipientInfo  pkRecInfo = new PKRecipientInfo(new HashedId8(keyHash), encKey);
		return new RecipientInfo(RecipientInfoChoices.rekRecipInfo, pkRecInfo);
	}
}
