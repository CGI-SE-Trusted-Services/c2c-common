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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedDataPayload;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HashedData.HashedDataChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.junit.Ignore;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for SignedDataPayload
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class SignedDataPayloadSpec extends BaseStructSpec {

	
	Opaque o = new Opaque(Hex.decode("0102030405060708"))
	Ieee1609Dot2Content content = new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.unsecuredData,o)
	Ieee1609Dot2Data data = new Ieee1609Dot2Data(content)
	HashedData extHash = new HashedData(HashedDataChoices.sha256HashedData, Hex.decode("0102030405060708091011121314151617181920212223242526272829303132"))
    SignedDataPayload sdp = new SignedDataPayload(data, extHash)
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		expect:
		sdp.hasExtension
		serializeToHex(sdp) == "600380080102030405060708800102030405060708091011121314151617181920212223242526272829303132"
		when:
		SignedDataPayload sdp2 = deserializeFromHex(new SignedDataPayload(), "600380080102030405060708800102030405060708091011121314151617181920212223242526272829303132")
		then:
		sdp2.hasExtension
		sdp2.getData() == data
		sdp2.getExtDataHash() == extHash
		
		
	}
	
	def "Verify that IOException is thrown if both data and exthash is null"(){
		when:
		new SignedDataPayload(null,null)
		then:
		thrown IOException
	} 
	

	def "Verify toString"(){
		expect:
		sdp.toString() == """SignedDataPayload [
  data=[
    protocolVersion=3,
    content=[
      unsecuredData=[data=0102030405060708]
    ]
  ],
  extDataHash=[sha256HashedData=0102030405060708091011121314151617181920212223242526272829303132]
]"""
		new SignedDataPayload(data,null).toString() == """SignedDataPayload [
  data=[
    protocolVersion=3,
    content=[
      unsecuredData=[data=0102030405060708]
    ]
  ]
]"""
		new SignedDataPayload(null, extHash).toString() == """SignedDataPayload [
  extDataHash=[sha256HashedData=0102030405060708091011121314151617181920212223242526272829303132]
]"""
	}
	

}
