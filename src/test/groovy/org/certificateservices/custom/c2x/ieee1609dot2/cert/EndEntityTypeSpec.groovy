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
package org.certificateservices.custom.c2x.ieee1609dot2.cert

import java.awt.Choice;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERNull
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfOctetString;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SequenceOfPsidSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.VerificationKeyIndicator.VerificationKeyIndicatorChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for EndEntityType
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EndEntityTypeSpec extends BaseStructSpec {
		
	@Unroll
	def "Verify that EndEntityType is correctly encoded #encoding for app #app and enroll #enroll"(){
		setup:
		String hexEncode = Integer.toHexString(Integer.parseInt(encoding,2))
		if(hexEncode.length() == 1){
			hexEncode = "0" + hexEncode;
		}
		when:
		EndEntityType ee = new EndEntityType(app,enroll)
		
		then:
		serializeToHex(ee) == hexEncode
		
		when:
		EndEntityType ee2 = deserializeFromHex(new EndEntityType(),hexEncode)
		
		then:
		ee2.isApp() == app
		ee2.isEnroll() == enroll
		
		where:
		app  | enroll   | encoding   
		true | true     | "11000000"
		false| true     | "1000000"
		true | false    | "10000000"
		false| false    | "00000000"
		      
	}

	
	def "Verify toString"(){
		expect:
		new EndEntityType(true,false).toString() == "EndEntityType [app=true, enroll=false]"
	}
	

}
