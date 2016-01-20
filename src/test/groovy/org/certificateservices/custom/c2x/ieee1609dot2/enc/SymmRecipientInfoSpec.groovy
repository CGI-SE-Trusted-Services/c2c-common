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
package org.certificateservices.custom.c2x.ieee1609dot2.enc

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EciesP256EncryptedKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;
import org.junit.Ignore;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SymmRecipientInfo
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class SymmRecipientInfoSpec extends BaseStructSpec {
	
	byte[] nounce = Hex.decode("010203040506070809101112")
	byte[] ccmCiphertext = Hex.decode("11121314")
	AesCcmCiphertext acc = new AesCcmCiphertext(nounce,ccmCiphertext)

	HashedId8 recepientId = new HashedId8(Hex.decode("0102030405060708"))
	SymmetricCiphertext encKey = new SymmetricCiphertext(acc)
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		SymmRecipientInfo ri1 = new SymmRecipientInfo(recepientId,encKey)
		then:
		serializeToHex(ri1) == "0102030405060708800102030405060708091011120411121314"
		when:
		SymmRecipientInfo ri2 = deserializeFromHex(new SymmRecipientInfo(), "0102030405060708800102030405060708091011120411121314")
		then:
		ri2.getRecipientId() == recepientId
		ri2.getEncKey() == encKey
	
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new SymmRecipientInfo(null, encKey)
		then:
		thrown IllegalArgumentException
		when:
		new SymmRecipientInfo(recepientId,null)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new SymmRecipientInfo(recepientId,encKey).toString() == "SymmRecipientInfo [recipientId=[0102030405060708], encKey=[aes128ccm=[nounce=010203040506070809101112, ccmCipherText=11121314]]]"
	}
	

}
