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


import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP384CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP384CurvePoint.EccP384CurvePointChoices
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.UncompressedEccPoint
import spock.lang.Shared
import spock.lang.Unroll

/**
 * Test for EccP384CurvePoint
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EccP384CurvePointSpec extends BaseStructSpec {
	
	@Shared BigInteger x = new BigInteger("66c6e8224be771b3fbad0bce972be456f1037f6714dde5eec129e3c4d1c858e7080756e3512438d2d8f0ab7bad5342d5",16)
	@Shared BigInteger y= new BigInteger("e3832e72c94e11059c9b64f8a54913c5a8e50232bb1671cc4abe7246bb7429306730e2e785893eaccce7a7dab779ca0a",16)
	@Shared byte[] compressed = Hex.decode("0266c6e8224be771b3fbad0bce972be456f1037f6714dde5eec129e3c4d1c858e7080756e3512438d2d8f0ab7bad5342d5")

	@Unroll
	def "Verify that EccP384CurvePoint is correctly encoded for type #choice"(){
		when:
		def p = value
		
		then:
		serializeToHex(p) == encoding
		
		when:
		EccP384CurvePoint p2 = deserializeFromHex(new EccP384CurvePoint(), encoding)
		
		then:
		
		if(choice == EccP384CurvePointChoices.uncompressed){
		  	assert new BigInteger(1,((UncompressedEccPoint) p2.value).getX()) == x
			assert new BigInteger(1,((UncompressedEccPoint) p2.value).getY()) == y
		}else{
		  if(choice == EccP384CurvePointChoices.xonly){
			assert new BigInteger(1, p2.value.data) == x  
		  }else{
		    byte[] compData = new byte[compressed.length -1]
			System.arraycopy(compressed, 1, compData, 0, compData.length)
		    assert p2.value.data == compData
		  }
		}
		p.choice == choice
		p.type == choice
		!choice.extension
		
		where:
		choice                                | value                             | encoding   
		EccP384CurvePointChoices.xonly        | new EccP384CurvePoint(x)          | "8066c6e8224be771b3fbad0bce972be456f1037f6714dde5eec129e3c4d1c858e7080756e3512438d2d8f0ab7bad5342d5"
		EccP384CurvePointChoices.compressedy0 | new EccP384CurvePoint(compressed) | "8266c6e8224be771b3fbad0bce972be456f1037f6714dde5eec129e3c4d1c858e7080756e3512438d2d8f0ab7bad5342d5"
		EccP384CurvePointChoices.uncompressed | new EccP384CurvePoint(x,y)        | "8466c6e8224be771b3fbad0bce972be456f1037f6714dde5eec129e3c4d1c858e7080756e3512438d2d8f0ab7bad5342d5e3832e72c94e11059c9b64f8a54913c5a8e50232bb1671cc4abe7246bb7429306730e2e785893eaccce7a7dab779ca0a"

		
	}
	
	def "Verify toString"(){
		expect:
		new EccP384CurvePoint(x).toString() == "EccP384CurvePoint [xonly=66c6e8224be771b3fbad0bce972be456f1037f6714dde5eec129e3c4d1c858e7080756e3512438d2d8f0ab7bad5342d5]"
		new EccP384CurvePoint(compressed).toString() == "EccP384CurvePoint [compressedy0=66c6e8224be771b3fbad0bce972be456f1037f6714dde5eec129e3c4d1c858e7080756e3512438d2d8f0ab7bad5342d5]"
		new EccP384CurvePoint(x,y).toString() == "EccP384CurvePoint [uncompressed=[x=66c6e8224be771b3fbad0bce972be456f1037f6714dde5eec129e3c4d1c858e7080756e3512438d2d8f0ab7bad5342d5, y=e3832e72c94e11059c9b64f8a54913c5a8e50232bb1671cc4abe7246bb7429306730e2e785893eaccce7a7dab779ca0a]]"
	}
	

}
