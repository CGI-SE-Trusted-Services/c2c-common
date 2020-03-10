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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic

import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EciesP256EncryptedKey;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for EciesP256EncryptedKey
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class EciesP256EncryptedKeySpec extends BaseStructSpec {

	
	EccP256CurvePoint v = new EccP256CurvePoint(new BigInteger(123))
	byte[] c = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),16)
	byte[] t = COEREncodeHelper.padZerosToByteArray(new BigInteger(467).toByteArray(),16)
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		EciesP256EncryptedKey k1 = new EciesP256EncryptedKey(v,c,t)
		then:
		serializeToHex(k1) == "80000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3"
		when:
		EciesP256EncryptedKey k2 = deserializeFromHex(new EciesP256EncryptedKey(), "80000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3")
		then:
		k2.getV() == v
		new BigInteger(1,k2.getC()).intValue() == 245
		new BigInteger(1,k2.getT()).intValue() == 467
	}
	
	def "Verify that IOException is thrown when encoding if not all fields are set"(){
		when:
		new EciesP256EncryptedKey(v,c,null)
		then:
		thrown IOException
		when:
		new EciesP256EncryptedKey(null,c,t)
		then:
		thrown IOException
		when:
		new EciesP256EncryptedKey(v,null,t)
		then:
		thrown IOException
	} 
	

	def "Verify toString"(){
		expect:
		new EciesP256EncryptedKey(v,c,t).toString() == "EciesP256EncryptedKey [v=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=000000000000000000000000000000f5, t=000000000000000000000000000001d3]"
	}
	

}
