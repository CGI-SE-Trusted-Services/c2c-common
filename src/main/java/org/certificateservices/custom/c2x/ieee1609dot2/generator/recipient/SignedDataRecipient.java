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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EncryptionKey.EncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedDataEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PKRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo.RecipientInfoChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;

/**
 * Receipient using public key based on signed data structure.
 * 
 * @author Philip Vendil p.vendil@cgi.com
 *
 */
public class SignedDataRecipient extends BasePKRecipient{
	
	private Ieee1609Dot2Data signedData;
	
	public SignedDataRecipient(Ieee1609Dot2Data signedData) throws BadArgumentException{
		this.signedData = signedData;
		if(signedData.getContent().getType() != Ieee1609Dot2ContentChoices.signedData){
			throw new BadArgumentException("Invalid SignedData used for PK Receiptient, must be of type signedData.");
		}
		
		EncryptionKey encKey = ((SignedData) signedData.getContent().getValue()).getTbsData().getHeaderInfo().getEncryptionKey();
				
		if(encKey== null){
			throw new BadArgumentException("Error supplied Signed Data didn't contain any encryption key in it's header info.");
		}
		if(encKey.getType() != EncryptionKeyChoices.public_){
			throw new BadArgumentException("Error supplied Signed Data didn't contain any encryption key in it's header info with type public key.");
		}
	}

	@Override
	public RecipientInfo toRecipientInfo(AlgorithmIndicator alg,
			Ieee1609Dot2CryptoManager cryptoManager, SecretKey encryptionKey)
			throws BadArgumentException, GeneralSecurityException,
			IOException {
		EncryptionKey eK = ((SignedData) signedData.getContent().getValue()).getTbsData().getHeaderInfo().getEncryptionKey();
		PublicEncryptionKey pubEncKey = (PublicEncryptionKey) eK.getValue();
		BasePublicEncryptionKey basePubEncKey = pubEncKey.getPublicKey();
		AlgorithmIndicator pubKeyAlg = basePubEncKey.getType();
		PublicKey certEncKey = (PublicKey) cryptoManager.decodeEccPoint(pubKeyAlg, (EccP256CurvePoint) basePubEncKey.getValue());
		
		byte[] dataHash = cryptoManager.digest(signedData.getEncoded(), HashAlgorithm.sha256);
		EncryptedDataEncryptionKey encKey = cryptoManager.ieeeEceisEncryptSymmetricKey2017(getEncKeyType(pubEncKey.getPublicKey().getType()), certEncKey, encryptionKey, dataHash);
		
		PKRecipientInfo  pkRecInfo = new PKRecipientInfo(new HashedId8(dataHash), encKey);
		return new RecipientInfo(RecipientInfoChoices.signedDataRecipInfo, pkRecInfo);
	}

}
