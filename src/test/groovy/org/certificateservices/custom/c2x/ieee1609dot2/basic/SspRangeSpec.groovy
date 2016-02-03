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
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange.SspRangeChoices;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SspRange
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SspRangeSpec extends BaseStructSpec {
	
	SequenceOfOctetString soc = new SequenceOfOctetString([new COEROctetStream("test1".getBytes()),new COEROctetStream("test2".getBytes())])
	
	@Unroll
	def "Verify that SspRange is correctly encoded for type #choice"(){
		when:
		def sr = new SspRange(choice, soc)
		
		then:
		serializeToHex(sr) == encoding
		
		when:
		SspRange sr2 = deserializeFromHex(new SspRange(), encoding)
		
		then:
		if(choice == SspRangeChoices.opaque){
		  sr2.getOpaqueData() == soc
		}
		sr2.choice == choice
		sr2.type == choice
		
		where:
		choice                                            | encoding   
		SspRangeChoices.opaque                            | "800102057465737431057465737432" 
		SspRangeChoices.all                               | "81"
		    

		
	}
	

	
	def "Verify toString"(){
		expect:
		new SspRange(SspRangeChoices.opaque, soc).toString() == "SspRange [opaque=[[COEROctetStream [data=7465737431],COEROctetStream [data=7465737432]]]]"
		new SspRange(SspRangeChoices.all, null).toString() == "SspRange [all]"
	}
	

}
