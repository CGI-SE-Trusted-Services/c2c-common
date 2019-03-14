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
import java.security.PrivateKey;

import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;

/**
 * Receiver using public key based on signed data structure.
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public class SignedDataReciever extends BasePKReceiver {

	private Ieee1609Dot2Data signedData;
	
	public SignedDataReciever(PrivateKey privateKey, Ieee1609Dot2Data signedData) {
		super(privateKey);
		this.signedData = signedData;
	}
	
	@Override
	protected byte[] getReferenceData() throws IOException {
		return signedData.getEncoded();
	}

	/**
	 * @return the hash algorithm used to calculate the related HashedId8 reference.
	 */
	@Override
	public AlgorithmIndicator getHashAlgorithm() {
		return HashAlgorithm.sha256; // Only sha256 signed data is supported using ecies.
	}
}
