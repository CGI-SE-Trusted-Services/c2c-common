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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;

/**
 * Receiver  using a pre-shared key.
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public class PreSharedKeyReceiver implements Receiver {

	private SecretKey secretKey;
	
	public PreSharedKeyReceiver(SecretKey secretKey){
		this.secretKey = secretKey;
	}
	
	@Override
	public HashedId8 getReference(AlgorithmIndicator alg, Ieee1609Dot2CryptoManager cryptoManager) throws IllegalArgumentException, GeneralSecurityException{
		return new HashedId8(cryptoManager.digest(secretKey.getEncoded(), alg));
	}

	@Override
	public SecretKey extractDecryptionKey(
			Ieee1609Dot2CryptoManager cryptoManager, RecipientInfo recipientInfo)
			throws IllegalArgumentException, GeneralSecurityException,
			IOException {
		return secretKey;
	}

	/**
	 * @return the hash algorithm used to calculate the related HashedId8 reference.
	 */
	@Override
	public AlgorithmIndicator getHashAlgorithm() {
		return HashAlgorithm.sha256;
	}


}
