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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EncryptionKey.EncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmetricEncryptionKey.SymmetricEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmetricEncryptionKey;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for EncryptionKey
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EncryptionKeySpec extends BaseStructSpec {
	
	@Shared EccP256CurvePoint p = new EccP256CurvePoint(new BigInteger(0x2023))
	@Shared BasePublicEncryptionKey pubKey = new BasePublicEncryptionKey(BasePublicEncryptionKeyChoices.ecdsaNistP256, p)
	@Shared PublicEncryptionKey pk = new PublicEncryptionKey(SymmAlgorithm.aes128Ccm,pubKey)
	
	@Shared byte[] k = COEREncodeHelper.padZerosToByteArray(Hex.decode("0100"),16);
	@Shared SymmetricEncryptionKey symmkey = new SymmetricEncryptionKey(SymmetricEncryptionKeyChoices.aes128Ccm,k)
	
	@Unroll
	def "Verify that EncryptionKey is correctly encoded for type #choice"(){
		when:
		def key = new EncryptionKey(value)
		
		then:
		serializeToHex(key) == encoding
		
		when:
		EncryptionKey key2 = deserializeFromHex(new EncryptionKey(), encoding)
		
		then:
		if(choice == EncryptionKeyChoices.public_){
		  key2.getValue() == pk
		}else{
		  key2.getValue() == symmkey
		}
		key2.choice == choice
		key2.type == choice
		
		where:
		choice                                              | value   | encoding   
		EncryptionKeyChoices.public_                        | pk      | "800080800000000000000000000000000000000000000000000000000000000000002023"   
		EncryptionKeyChoices.symmetric                      | symmkey | "818000000000000000000000000000000100"      
	
	}
	
	
	def "Verify toString"(){
		expect:
		new EncryptionKey(pk).toString() == "EncryptionKey [public_=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[xonly=0000000000000000000000000000000000000000000000000000000000002023]]]]"
		new EncryptionKey(symmkey).toString() == "EncryptionKey [symmetric=[aes128Ccm=00000000000000000000000000000100]]"
	}
	

}
