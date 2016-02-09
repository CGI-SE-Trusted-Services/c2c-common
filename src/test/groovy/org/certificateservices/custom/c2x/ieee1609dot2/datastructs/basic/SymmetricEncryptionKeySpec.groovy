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

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmetricEncryptionKey.SymmetricEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmetricEncryptionKey;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SymmetricEncryptionKey
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SymmetricEncryptionKeySpec extends BaseStructSpec {
	
	byte[] key = COEREncodeHelper.padZerosToByteArray(Hex.decode("0100"),16);

	@Unroll
	def "Verify that SymmetricEncryptionKey is correctly encoded for type #choice"(){
		when:
		def p = new SymmetricEncryptionKey(choice,key)
		
		then:
		serializeToHex(p) == encoding
		
		when:
		SymmetricEncryptionKey p2 = deserializeFromHex(new SymmetricEncryptionKey(), encoding)
		
		then:
		((COEROctetStream) p.value).getData() == key
	
		p.choice == choice
		p.type == choice
		
		where:
		choice                                   | encoding   
		SymmetricEncryptionKeyChoices.aes128Ccm  | "8000000000000000000000000000000100"     

		
	}
	
	def "Verify toString"(){
		expect:
		new SymmetricEncryptionKey(SymmetricEncryptionKeyChoices.aes128Ccm,key).toString() == "SymmetricEncryptionKey [aes128Ccm=00000000000000000000000000000100]"
	}
	

}
