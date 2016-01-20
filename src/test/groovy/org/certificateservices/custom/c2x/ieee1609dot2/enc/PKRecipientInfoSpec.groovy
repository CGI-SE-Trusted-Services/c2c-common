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
 * Test for PKRecipientInfo
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class PKRecipientInfoSpec extends BaseStructSpec {
	
	byte[] x = new BigInteger(123).toByteArray()
	EccP256CurvePoint v = new EccP256CurvePoint(EccP256CurvePointChoices.xonly,x)
	byte[] c = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),16)
	byte[] t = COEREncodeHelper.padZerosToByteArray(new BigInteger(467).toByteArray(),16)
	EciesP256EncryptedKey encKey = new EciesP256EncryptedKey(v,c,t)

	HashedId8 recepientId = new HashedId8(Hex.decode("0102030405060708"))
	EncryptedDataEncryptionKey encryptedDataEncryptionKey = new EncryptedDataEncryptionKey(EncryptedDataEncryptionKeyChoices.eciesNistP256, encKey)
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		PKRecipientInfo ri1 = new PKRecipientInfo(recepientId,encryptedDataEncryptionKey)
		then:
		serializeToHex(ri1) == "01020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3"
		when:
		PKRecipientInfo ri2 = deserializeFromHex(new PKRecipientInfo(), "01020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3")
		then:
		ri2.getRecipientId() == recepientId
		ri2.getEncKey() == encryptedDataEncryptionKey
	
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new PKRecipientInfo(null, encryptedDataEncryptionKey)
		then:
		thrown IllegalArgumentException
		when:
		new PKRecipientInfo(recepientId,null)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new PKRecipientInfo(recepientId,encryptedDataEncryptionKey).toString() == "PKRecipientInfo [recipientId=[0102030405060708], encKey=[eciesNistP256=[v=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=000000000000000000000000000000f5, t=000000000000000000000000000001d3]]]"
	}
	

}
