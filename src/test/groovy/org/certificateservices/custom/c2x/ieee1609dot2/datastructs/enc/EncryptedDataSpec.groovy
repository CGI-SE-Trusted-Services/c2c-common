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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.AesCcmCiphertext;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.PreSharedKeyRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SequenceOfRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmetricCiphertext;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for EncryptedData
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class EncryptedDataSpec extends BaseStructSpec {

	RecipientInfo ri1 = new RecipientInfo(new PreSharedKeyRecipientInfo(Hex.decode("0102030405060708")))
	RecipientInfo ri2 = new RecipientInfo(new PreSharedKeyRecipientInfo(Hex.decode("1112131415161718")))
	
	SequenceOfRecipientInfo sri = new SequenceOfRecipientInfo([ri1,ri2])
	
	
	byte[] nounce = Hex.decode("010203040506070809101112")
	byte[] ccmCiphertext = Hex.decode("11121314")
	
	SymmetricCiphertext sct = new SymmetricCiphertext(new AesCcmCiphertext(nounce,ccmCiphertext))
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		EncryptedData ed1 = new EncryptedData(sri,sct)
		then:
		serializeToHex(ed1) == "0102800102030405060708801112131415161718800102030405060708091011120411121314"
		when:
		EncryptedData ed2 = deserializeFromHex(new EncryptedData(), "0102800102030405060708801112131415161718800102030405060708091011120411121314")
		then:
		ed2.getRecipients() == sri
		ed2.getCipherText() == sct
	}
	
	def "Verify that IOException is thrown when encoding if not all fields are set"(){
		when:
		new EncryptedData(null, sct)
		then:
		thrown IOException
		when:
		new EncryptedData(sri,null)
		then:
		thrown IOException
	} 
	

	def "Verify toString"(){
		expect:
		new EncryptedData(sri,sct).toString() == """EncryptedData [
  recipients=[[pskRecipInfo=[0102030405060708]],[pskRecipInfo=[1112131415161718]]],
  ciphertext=[aes128ccm=[nounce=010203040506070809101112, ccmCipherText=11121314]]
]"""
	}
	

}
