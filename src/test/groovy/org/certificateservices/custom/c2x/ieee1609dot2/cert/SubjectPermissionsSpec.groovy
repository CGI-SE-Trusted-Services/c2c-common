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
 * Test for SubjectPermissions
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SubjectPermissionsSpec extends BaseStructSpec {
	
	@Shared Psid id1 = new Psid(101)
	@Shared Psid id2 = new Psid(64321)
	
	@Shared SequenceOfOctetString soc = new SequenceOfOctetString([new COEROctetStream("test1".getBytes()),new COEROctetStream("test2".getBytes())])
	@Shared SspRange ssprange1 = new SspRange(SspRangeChoices.all, null)
	@Shared SspRange ssprange2 = new SspRange(SspRangeChoices.opaque, soc)
	
	@Shared PsidSspRange psr1 = new PsidSspRange(id1,ssprange1)
	@Shared PsidSspRange psr2 = new PsidSspRange(id2,ssprange2)
	@Shared SequenceOfPsidSspRange perms = new SequenceOfPsidSspRange([psr1,psr2])
	
	@Unroll
	def "Verify that SubjectPermissions is correctly encoded for type #choice"(){
		when:
		def key = new SubjectPermissions(choice,value)
		
		then:
		serializeToHex(key) == encoding
		
		when:
		SubjectPermissions key2 = deserializeFromHex(new SubjectPermissions(), encoding)
		
		then:
		key2.getValue() == (choice==SubjectPermissionsChoices.explicit? value : new COERNull())
		key2.choice == choice
		key2.type == choice
		
		where:
		choice                                              | value   | encoding   
		SubjectPermissionsChoices.explicit	                | perms   | "800102400165814002fb41800102057465737431057465737432"   
		SubjectPermissionsChoices.all                       | null    | "81"      
	}

	
	def "Verify toString"(){
		expect:
		new SubjectPermissions(SubjectPermissionsChoices.explicit,perms).toString() == "SubjectPermissions [explicit=[[psid=[101(65)], sspRange=[all]],[psid=[64321(fb41)], sspRange=[opaque=[[COEROctetStream [data=7465737431],COEROctetStream [data=7465737432]]]]]]]"
		new SubjectPermissions(SubjectPermissionsChoices.all,null).toString() == "SubjectPermissions [all]"
	}
	

}
