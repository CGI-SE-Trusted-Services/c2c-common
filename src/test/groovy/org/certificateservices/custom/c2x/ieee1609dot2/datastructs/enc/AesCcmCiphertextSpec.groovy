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
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for AesCcmCiphertext
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class AesCcmCiphertextSpec extends BaseStructSpec {

	byte[] nounce = Hex.decode("010203040506070809101112")
	byte[] ccmCiphertext = Hex.decode("11121314")
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		AesCcmCiphertext acc1 = new AesCcmCiphertext(nounce,ccmCiphertext)
		then:
		serializeToHex(acc1) == "0102030405060708091011120411121314"
		when:
		AesCcmCiphertext acc2 = deserializeFromHex(new AesCcmCiphertext(), "0102030405060708091011120411121314")
		then:
		acc2.getNounce() == nounce
		acc2.getCcmCipherText() == ccmCiphertext
	
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new AesCcmCiphertext(null, ccmCiphertext)
		then:
		thrown IllegalArgumentException
		when:
		new AesCcmCiphertext(nounce,null)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new AesCcmCiphertext(nounce,ccmCiphertext).toString() == "AesCcmCiphertext [nounce=010203040506070809101112, ccmCipherText=11121314]"
	}
	

}
