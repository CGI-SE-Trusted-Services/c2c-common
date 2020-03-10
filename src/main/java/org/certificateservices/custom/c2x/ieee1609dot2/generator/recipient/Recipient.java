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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;

/**
 * Generic interface for a recipient used during encryption.
 * <p>
 * A Recipient interface is used when sending data to others, Receiver is used when receiving data from others.
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public interface Recipient {

	/**
	 * Method to return a generated ReceiptientInfo for the given encryption key.
	 *  
	 */
	RecipientInfo toRecipientInfo(AlgorithmIndicator alg, Ieee1609Dot2CryptoManager cryptoManager,SecretKey encryptionKey) throws BadArgumentException, GeneralSecurityException, IOException;
	
	
}
