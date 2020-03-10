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
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PKRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo.RecipientInfoChoices;

/**
 * Recipient using a certificate to extract the public key.
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public class CertificateRecipient extends BasePKRecipient{
	
	Certificate certificate;
	
	
	
	public CertificateRecipient(Certificate certificate) throws BadArgumentException {
		if(certificate.getToBeSigned().getEncryptionKey() == null){
			throw new BadArgumentException("Error certificate cannot be used as encryption receipient, it has no public encryption key.");
		}
		
		this.certificate = certificate;
	}

	@Override
	public RecipientInfo toRecipientInfo(AlgorithmIndicator alg,
			Ieee1609Dot2CryptoManager cryptoManager, SecretKey encryptionKey)
			throws BadArgumentException, GeneralSecurityException, IOException {
		
		PublicEncryptionKey pubEncKey = certificate.getToBeSigned().getEncryptionKey();
		AlgorithmIndicator pubKeyAlg = pubEncKey.getPublicKey().getType();
		PublicKey certEncKey = (PublicKey) cryptoManager.decodeEccPoint(pubKeyAlg, (EccP256CurvePoint) pubEncKey.getPublicKey().getValue());
		
		byte[] certHash = cryptoManager.digest(certificate.getEncoded(), HashAlgorithm.sha256);
		EncryptedDataEncryptionKey encKey = cryptoManager.ieeeEceisEncryptSymmetricKey2017(getEncKeyType(pubEncKey.getPublicKey().getType()), certEncKey, encryptionKey,  certHash);
		
		PKRecipientInfo  pkRecInfo = new PKRecipientInfo(new HashedId8(certHash), encKey);
		return new RecipientInfo(RecipientInfoChoices.certRecipInfo, pkRecInfo);
	}

	

}
