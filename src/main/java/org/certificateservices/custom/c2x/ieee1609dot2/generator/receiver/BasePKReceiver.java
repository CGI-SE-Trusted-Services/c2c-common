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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

import javax.crypto.SecretKey;

import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PKRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;

/**
 * Base class containing common methods for all Public Key Receivers.
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public  abstract class BasePKReceiver implements Receiver {

	protected PrivateKey privateKey;
	
	protected BasePKReceiver(PrivateKey privateKey){
		this.privateKey = privateKey;
	}
	
	@Override
	public HashedId8 getReference(AlgorithmIndicator alg, Ieee1609Dot2CryptoManager cryptoManager) throws IllegalArgumentException, GeneralSecurityException, IOException{		
		return new HashedId8(getHashedReference(alg, cryptoManager));
	}
	
	@Override
	public SecretKey extractDecryptionKey(
			Ieee1609Dot2CryptoManager cryptoManager, RecipientInfo recipientInfo)
			throws IllegalArgumentException, GeneralSecurityException,
			IOException {
		PKRecipientInfo pkRecInfo = (PKRecipientInfo) recipientInfo.getValue();
		
		return cryptoManager.eCEISDecryptSymmetricKey(pkRecInfo.getEncKey(), privateKey, pkRecInfo.getEncKey().getType(), getHashedReference(pkRecInfo.getEncKey().getType(), cryptoManager));
	}

	private byte[] hashReference = null;
	/**
	 * Help method to retrieve the hashed reference data used for HashedId8 and deviation.
	 */
	protected byte[] getHashedReference(AlgorithmIndicator alg, CryptoManager cryptoManager) throws IllegalArgumentException, NoSuchAlgorithmException, IOException{
		if(hashReference == null){
			hashReference = cryptoManager.digest(getReferenceData(), alg);
		}
		
		return hashReference;
	}
	
	protected abstract byte[] getReferenceData() throws IOException;
}
