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

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices;

/**
 * Base class containing common methods for all Public Key Recipients.
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public abstract class BasePKRecipient implements Recipient {


	protected EncryptedDataEncryptionKeyChoices getEncKeyType(AlgorithmIndicator alg) throws BadArgumentException {
		if(alg.getAlgorithm().getSignature() == null){
			throw new BadArgumentException("Error unsupported algorithm: " + alg);
		}

		switch(alg.getAlgorithm().getSignature()){
		case ecdsaNistP256:
			return EncryptedDataEncryptionKeyChoices.eciesNistP256;
		case ecdsaBrainpoolP256r1:
		default:
			return EncryptedDataEncryptionKeyChoices.eciesBrainpoolP256r1;
		}
	}

}
