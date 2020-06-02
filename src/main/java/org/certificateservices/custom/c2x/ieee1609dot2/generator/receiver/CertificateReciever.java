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

import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;

/**
 * Receiver  using a certificate to envelope decryption key.
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public class CertificateReciever extends BasePKReceiver {

	private Certificate certificate;
	
	/**
	 * Default constructor
	 * 
	 * @param privateKey private key 
	 * @param certificate the related certificate.
	 */
	public CertificateReciever(PrivateKey privateKey, Certificate certificate){
		super(privateKey);
		this.certificate = certificate;
	}

	/**
	 *
	 * @return the related certificate for the receiver.
	 */
	public Certificate getCertificate(){
		return certificate;
	}
	
	@Override
	protected byte[] getReferenceData() throws IOException {
		return certificate.getEncoded();
	}

	@Override
	public AlgorithmIndicator getHashAlgorithm() {
		if(certificate.getSignature() != null){
			certificate.getSignature().getType().getAlgorithm();
		}
		return HashAlgorithm.sha256;
	}


}
