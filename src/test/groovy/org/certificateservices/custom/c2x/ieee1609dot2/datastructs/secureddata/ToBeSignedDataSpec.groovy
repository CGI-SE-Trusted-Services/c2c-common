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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedDataPayload;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.ToBeSignedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData.HashedDataChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.junit.Ignore;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for MissingCrlIdentifier
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class ToBeSignedDataSpec extends BaseStructSpec {

    SignedDataPayload sdp = new SignedDataPayload(null, new HashedData(HashedDataChoices.sha256HashedData, Hex.decode("0102030405060708091011121314151617181920212223242526272829303132")))
	HeaderInfo hi = new HeaderInfo(new Psid(100), null, null, null, null, null, null, null,null)
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		ToBeSignedData tbs1 = new ToBeSignedData(sdp,hi)
		then:
		!tbs1.hasExtension
		serializeToHex(tbs1) == "20800102030405060708091011121314151617181920212223242526272829303132000164"
		when:
		ToBeSignedData tbs2 = deserializeFromHex(new ToBeSignedData(), "20800102030405060708091011121314151617181920212223242526272829303132000164")
		then:
		!tbs2.hasExtension
		tbs2.getPayload() == sdp
		tbs2.getHeaderInfo() == hi
		
	}
	
	def "Verify that encode and decode to byte array is correct"(){
		when:
		ToBeSignedData tbs1 = new ToBeSignedData(sdp,hi)
		ToBeSignedData tbs2 = new ToBeSignedData(tbs1.encoded)
		then:
		tbs1 == tbs2
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all required fields are set"(){
		when:
		new ToBeSignedData(null,hi)
		then:
		thrown IllegalArgumentException
		when:
		new ToBeSignedData(sdp,null)
		then:
		thrown IllegalArgumentException
		
	} 
	

	def "Verify toString"(){
		expect:
		new ToBeSignedData(sdp,hi).toString() == """ToBeSignedData [
  payload=[
    extDataHash=[sha256HashedData=0102030405060708091011121314151617181920212223242526272829303132]
  ],
  headerInfo=[
    psid=[100(64)]
  ]
]"""
	}
	

}
