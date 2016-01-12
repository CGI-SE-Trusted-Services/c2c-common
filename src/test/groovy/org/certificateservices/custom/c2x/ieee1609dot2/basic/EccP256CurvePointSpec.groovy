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

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for EccP256CurvePoint
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EccP256CurvePointSpec extends BaseStructSpec {
	
	byte[] x = Hex.decode("0100");
	byte[] y = Hex.decode("0200");

	@Unroll
	def "Verify that EccP256CurvePoint is correctly encoded for type #choice"(){
		when:
		def p = (choice ==  EccP256CurvePointChoices.uncompressed ? new EccP256CurvePoint(x,y) : new EccP256CurvePoint(choice,x))
		
		then:
		serializeToHex(p) == encoding
		
		when:
		EccP256CurvePoint p2 = deserializeFromHex(new EccP256CurvePoint(), encoding)
		
		then:
		
		if(choice == EccP256CurvePointChoices.uncompressed){
		  	((UncompressedEccPoint) p.value).getX() == x
			((UncompressedEccPoint) p.value).getY() == y
		}else{
		  ((COEROctetStream) p.value).getData() == x
		}
		p.choice == choice
		p.type == choice
		
		where:
		choice                                | encoding   
		EccP256CurvePointChoices.xonly        | "800000000000000000000000000000000000000000000000000000000000000100"   
		EccP256CurvePointChoices.compressedy0 | "820000000000000000000000000000000000000000000000000000000000000100"   
		EccP256CurvePointChoices.compressedy1 | "830000000000000000000000000000000000000000000000000000000000000100"   
		EccP256CurvePointChoices.uncompressed | "8400000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200"   

		
	}
	
	def "Verify toString"(){
		expect:
		new EccP256CurvePoint(EccP256CurvePointChoices.xonly,x).toString() == "EccP256CurvePoint [xonly=0000000000000000000000000000000000000000000000000000000000000100]"
		new EccP256CurvePoint(x,y).toString() == "EccP256CurvePoint [uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000100, y=0000000000000000000000000000000000000000000000000000000000000200]]"
	}
	

}
