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

import javax.crypto.SecretKey;

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmetricEncryptionKey;
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
	private AlgorithmIndicator symKeyAlg;
	
	/**
	 * 
	 * @param symmetricKey enveloping symmetric key.
	 */
	public SymmetricKeyReceipient(AlgorithmIndicator symKeyAlg,SecretKey symmetricKey){
		this.symmetricKey = symmetricKey;
		this.symKeyAlg = symKeyAlg;
	}
	
	@Override
	public RecipientInfo toRecipientInfo(AlgorithmIndicator alg,Ieee1609Dot2CryptoManager cryptoManager, SecretKey encryptionKey) throws BadArgumentException, GeneralSecurityException {
		
		byte[] nounce = cryptoManager.genNounce(alg);
		byte[] encData = cryptoManager.symmetricEncryptIEEE1609_2_2017(alg, encryptionKey.getEncoded(), symmetricKey.getEncoded(), nounce);
		try {
			SymmetricCiphertext symmetricCiphertext;
			switch (alg.getAlgorithm().getSymmetric()) {
				case aes128Ccm:
				default:
					symmetricCiphertext = new SymmetricCiphertext(new AesCcmCiphertext(nounce, encData));
			}

			SymmetricEncryptionKey.SymmetricEncryptionKeyChoices choice = SymmetricEncryptionKey.SymmetricEncryptionKeyChoices.getChoiceFromAlgorithm(symKeyAlg);
			SymmetricEncryptionKey symmetricEncryptionKey = new SymmetricEncryptionKey(choice, symmetricKey.getEncoded());
			HashedId8 recipientId = new HashedId8(cryptoManager.digest(symmetricEncryptionKey.getEncoded(), alg));
			SymmRecipientInfo symmRecipientInfo = new SymmRecipientInfo(recipientId, symmetricCiphertext);
			return new RecipientInfo(symmRecipientInfo);
		} catch (IOException e) {
			throw new BadArgumentException("Invalid encoded SymmRecipientInfo when calculated the hashedId8 for recipient: " + e.getMessage(), e);
		}
	}

}
