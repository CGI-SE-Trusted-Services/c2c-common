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

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmetricEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmetricCiphertext;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;


/**
 * Receiver when enveloping the symmetric encryption key with another symmetric key.
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public class SymmetricKeyReceiver implements Receiver {
	
	private SecretKey symmetricKey;
	private AlgorithmIndicator symKeyAlg;
	
	public SymmetricKeyReceiver(AlgorithmIndicator symKeyAlg,SecretKey symmetricKey){
		this.symmetricKey = symmetricKey;
		this.symKeyAlg = symKeyAlg;
	}

	@Override
	public HashedId8 getReference(AlgorithmIndicator alg, CryptoManager cryptoManager) throws BadArgumentException, GeneralSecurityException {
		try {
			SymmetricEncryptionKey.SymmetricEncryptionKeyChoices choice = SymmetricEncryptionKey.SymmetricEncryptionKeyChoices.getChoiceFromAlgorithm(symKeyAlg);
			SymmetricEncryptionKey symmetricEncryptionKey = new SymmetricEncryptionKey(choice, symmetricKey.getEncoded());

			return new HashedId8(cryptoManager.digest(symmetricEncryptionKey.getEncoded(), alg));
		} catch (IOException e) {
			throw new BadArgumentException("Invalid encoded SymmetricKey when calculated the hashedId8 for receiver: " + e.getMessage(), e);
		}
	}

	@Override
	public SecretKey extractDecryptionKey(
			Ieee1609Dot2CryptoManager cryptoManager, RecipientInfo recipientInfo)
			throws BadArgumentException, GeneralSecurityException {
		SymmRecipientInfo sri = (SymmRecipientInfo) recipientInfo.getValue();
		
		SymmetricCiphertext symmetricCiphertext = sri.getEncKey();

		byte[] keyData = cryptoManager.symmetricDecryptIEEE1609_2_2017(symmetricCiphertext.getType(), SecuredDataGenerator.getEncryptedData(symmetricCiphertext), symmetricKey.getEncoded(), SecuredDataGenerator.getNounce(symmetricCiphertext));
		return cryptoManager.constructSecretKey(symmetricCiphertext.getType(), keyData);
	}

	/**
	 * @return the hash algorithm used to calculate the related HashedId8 reference.
	 */
	@Override
	public AlgorithmIndicator getHashAlgorithm() {
		return HashAlgorithm.sha256;
	}
}
