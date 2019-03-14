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

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.AesCcmCiphertext;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmetricCiphertext;

/**
 * Receiptent when enveloping the symmetric encryption key with another symmetric key.
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public class SymmetricKeyReceipient implements Recipient {

	private SecretKey symmetricKey;
	
	/**
	 * 
	 * @param symmetricKey enveloping symmetric key.
	 */
	public SymmetricKeyReceipient(SecretKey symmetricKey){
		this.symmetricKey = symmetricKey;
	}
	
	@Override
	public RecipientInfo toRecipientInfo(AlgorithmIndicator alg,Ieee1609Dot2CryptoManager cryptoManager, SecretKey encryptionKey) throws IllegalArgumentException, GeneralSecurityException {
		
		byte[] nounce = cryptoManager.genNounce(alg);
		byte[] encData = cryptoManager.symmetricEncryptIEEE1609_2_2017(alg, encryptionKey.getEncoded(), symmetricKey.getEncoded(), nounce);
		SymmetricCiphertext symmetricCiphertext;
		switch (alg.getAlgorithm().getSymmetric()) {
		case aes128Ccm:
		default:
			symmetricCiphertext = new SymmetricCiphertext(new AesCcmCiphertext(nounce, encData));
		}
		
		HashedId8 recipientId = new HashedId8(cryptoManager.digest(symmetricKey.getEncoded(), alg));
		SymmRecipientInfo symmRecipientInfo = new SymmRecipientInfo(recipientId, symmetricCiphertext);
		return new RecipientInfo(symmRecipientInfo);
	}

}
