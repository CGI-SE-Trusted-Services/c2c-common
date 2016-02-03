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
package org.certificateservices.custom.c2x.ieee1609dot2.secureddata

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.junit.Ignore;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Ieee1609Dot2Data
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class Ieee1609Dot2DataSpec extends BaseStructSpec {

    Opaque o = new Opaque(Hex.decode("0102030405060708"))
	Ieee1609Dot2Content content = new Ieee1609Dot2Content(Ieee1609Dot2ContentChoices.unsecuredData,o)
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		Ieee1609Dot2Data d2d1 = new Ieee1609Dot2Data(4,content)
		then:
		!d2d1.hasExtension
		serializeToHex(d2d1) == "0480080102030405060708"
		when:
		Ieee1609Dot2Data d2d2 = deserializeFromHex(new Ieee1609Dot2Data(), "0480080102030405060708")
		then:
		!d2d2.hasExtension
		d2d2.getProtocolVersion() == 4
		d2d2.getContent() == content
		when:
		Ieee1609Dot2Data d2d3 = new Ieee1609Dot2Data(content)
		then:
		d2d3.getProtocolVersion() == 3
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all required fields are set"(){
		when:
		new Ieee1609Dot2Data((Ieee1609Dot2Content) null)
		then:
		thrown IllegalArgumentException
		
	} 
	
	byte[] referenceDataStruct = Hex.decode("0381004003800F5468697320697320612042534D0D0A4001201112131415161718810101000301802122232425262728508080006431323334353637383941424344515253545556575859616263004604E09A208400A983010380007C8001E4800348010200012000012681829192939495969798919293949596979891929394959697989192939495969798808231323334353637383132333435363738313233343536373831323334353637384142434445464748414243444546474841424344454647484142434445464748")
	
	
	def "Verify that reference structure from D.5.2.2 of P1909.2_D12 is parsed and regenerated correctly"(){
		when:
		Ieee1609Dot2Data d = new Ieee1609Dot2Data(referenceDataStruct)
		then:
		d.toString() == """Ieee1609Dot2Data [
  protocolVersion=3,
  content=[
    signedData=[
      hashAlgorithm=sha256,
      tbsData=[
        payload=[
          data=[
            protocolVersion=3,
            content=[
              unsecuredData=[data=5468697320697320612042534d0d0a]
            ]
          ]
        ],
        headerInfo=[
          psid=[32(20)],
          generationTime=[timeStamp=Sat Apr 05 07:39:56 CEST 40983 (1230066625199609624)]
        ]
      ],
      signer=[certificate=[
      Certificate [
        version=3
        type=implicit
        issuer=[sha256AndDigest=[2122232425262728]]
        toBeSigned=[
          id=[linkageData=[iCert=[100], linkage-value=[313233343536373839], group-linkage-value=[jvalue=41424344, value=515253545556575859]]]
          cracaId=[616263]
          crlSeries=[70]
          validityPeriod=[start=Time32 [timeStamp=Sat Aug 05 04:06:23 CEST 2006 (81828384)], duration=Duration [169 hours]]
          region=[SequenceOfIdentifiedRegion [[CountryOnly [124]],[CountryOnly [484]],[CountryOnly [840]]]]
          assuranceLevel=NONE
          appPermissions=[[psid=[32(20)], ssp=NULL],[psid=[38(26)], ssp=NULL]]
          certIssuePermissions=NONE
          certRequestPermissions=NONE
          canRequestRollover=false
          encryptionKey=NONE
          verifyKeyIndicator=[reconstructionValue=[compressedy0=9192939495969798919293949596979891929394959697989192939495969798]]
        ]
        signature=NONE
      ]]],
      signature=[ecdsaNistP256Signature=EcdsaP256[r=[compressedy0=3132333435363738313233343536373831323334353637383132333435363738], s=4142434445464748414243444546474841424344454647484142434445464748]]
    ]
  ]
]"""
		d.encoded == referenceDataStruct
	}
	
	
	def "Verify toString"(){
		expect:
		new Ieee1609Dot2Data(content).toString() == """Ieee1609Dot2Data [
  protocolVersion=3,
  content=[
    unsecuredData=[data=0102030405060708]
  ]
]"""
	}
	

}
