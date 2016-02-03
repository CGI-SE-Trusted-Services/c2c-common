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
package org.certificateservices.custom.c2x.ieee1609dot2.basic

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;

import spock.lang.Shared
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for EccP256CurvePoint
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EccP256CurvePointSpec extends BaseStructSpec {
	
	@Shared BigInteger x = new BigInteger("5563e78f842b20526344674f7ebcccdcf4266c66a63d068411479a2a2c2d62f7",16)
	@Shared BigInteger y= new BigInteger("bbeda771dd0d9951ec61adbed50013584c1488d63a924d44625cf70b487e4d01",16)
	@Shared byte[] compressed = Hex.decode("03ddcb45434eccff340f384cf4bfa202cb43baaabc741abd39a3dcb263464ad085")
	
	
	@Unroll
	def "Verify that EccP256CurvePoint is correctly encoded for type #choice"(){
		when:
		def p = value
		
		then:
		serializeToHex(p) == encoding
		
		when:
		EccP256CurvePoint p2 = deserializeFromHex(new EccP256CurvePoint(), encoding)
		
		then:
		
		if(choice == EccP256CurvePointChoices.uncompressed){
		  	assert new BigInteger(1,((UncompressedEccPoint) p2.value).getX()) == x
			assert new BigInteger(1,((UncompressedEccPoint) p2.value).getY()) == y
		}else{
		  if(choice == EccP256CurvePointChoices.xonly){
			assert new BigInteger(1, p2.value.data) == x  
		  }else{
		    byte[] compData = new byte[compressed.length -1]
			System.arraycopy(compressed, 1, compData, 0, compData.length)
		    assert p2.value.data == compData
		  }
		}
		p.choice == choice
		p.type == choice
		
		where:
		choice                                | value                             | encoding   
		EccP256CurvePointChoices.xonly        | new EccP256CurvePoint(x)          | "805563e78f842b20526344674f7ebcccdcf4266c66a63d068411479a2a2c2d62f7"   
		EccP256CurvePointChoices.compressedy1 | new EccP256CurvePoint(compressed) | "83ddcb45434eccff340f384cf4bfa202cb43baaabc741abd39a3dcb263464ad085"   
		EccP256CurvePointChoices.uncompressed | new EccP256CurvePoint(x,y)        | "845563e78f842b20526344674f7ebcccdcf4266c66a63d068411479a2a2c2d62f7bbeda771dd0d9951ec61adbed50013584c1488d63a924d44625cf70b487e4d01"   

		
	}
	
	def "Verify toString"(){
		expect:
		new EccP256CurvePoint(x).toString() == "EccP256CurvePoint [xonly=5563e78f842b20526344674f7ebcccdcf4266c66a63d068411479a2a2c2d62f7]"
		new EccP256CurvePoint(compressed).toString() == "EccP256CurvePoint [compressedy1=ddcb45434eccff340f384cf4bfa202cb43baaabc741abd39a3dcb263464ad085]"
		new EccP256CurvePoint(x,y).toString() == "EccP256CurvePoint [uncompressed=[x=5563e78f842b20526344674f7ebcccdcf4266c66a63d068411479a2a2c2d62f7, y=bbeda771dd0d9951ec61adbed50013584c1488d63a924d44625cf70b487e4d01]]"
	}
	

}
