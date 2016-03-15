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

import javax.crypto.SecretKey;

import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmetricCiphertext;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator;


/**
 * Receiver when enveloping the symmetric encryption key with another symmetric key.
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public class SymmetricKeyReceiver implements Receiver {
	
	private SecretKey symmetricKey;
	
	public SymmetricKeyReceiver(SecretKey symmetricKey){
		this.symmetricKey = symmetricKey;
	}

	@Override
	public HashedId8 getReference(AlgorithmIndicator alg, Ieee1609Dot2CryptoManager cryptoManager) throws IllegalArgumentException, GeneralSecurityException {
		return new HashedId8(cryptoManager.digest(symmetricKey.getEncoded(), alg));
	}

	@Override
	public SecretKey extractDecryptionKey(
			Ieee1609Dot2CryptoManager cryptoManager, RecipientInfo recipientInfo)
			throws IllegalArgumentException, GeneralSecurityException,
			IOException {
		SymmRecipientInfo sri = (SymmRecipientInfo) recipientInfo.getValue();
		
		SymmetricCiphertext symmetricCiphertext = sri.getEncKey();
		byte[] keyData = cryptoManager.symmetricDecrypt(symmetricCiphertext.getType(), SecuredDataGenerator.getEncryptedData(symmetricCiphertext), symmetricKey, SecuredDataGenerator.getNounce(symmetricCiphertext));
		return cryptoManager.constructSecretKey(symmetricCiphertext.getType(), keyData);
	}

}
