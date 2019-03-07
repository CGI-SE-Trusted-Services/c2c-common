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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
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

	String referenceDataStruct = "0381004003800F5468697320697320612042534D0D0A4001201112131415161718810101000301802122232425262728508080006431323334353637383941424344515253545556575859616263004604E09A208400A983010380007C8001E4800348010200012000012681829192939495969798919293949596979891929394959697989192939495969798808231323334353637383132333435363738313233343536373831323334353637384142434445464748414243444546474841424344454647484142434445464748".toLowerCase()

	String fromDoc2016_1 = normalizeHex """
03 81 00 40 03 80 0F 54 68 69 73 20 69 73 20 61
20 42 53 4D 0D 0A 40 01 20 11 12 13 14 15 16 17
18 80 21 22 23 24 25 26 27 28 80 82 31 32 33 34
35 36 37 38 31 32 33 34 35 36 37 38 31 32 33 34
35 36 37 38 31 32 33 34 35 36 37 38 41 42 43 44
45 46 47 48 41 42 43 44 45 46 47 48 41 42 43 44
45 46 47 48 41 42 43 44 45 46 47 48"""

	String fromDoc2016_2 = """
03 81 00 40 03 80 0F 54 68 69 73 20 69 73 20 61
20 42 53 4D 0D 0A 40 01 20 11 12 13 14 15 16 17
18 81 01 01 00 03 01 80 21 22 23 24 25 26 27 28
50 80 80 00 64 31 32 33 34 35 36 37 38 39 41 42
43 44 51 52 53 54 55 56 57 58 59 61 62 63 00 46
04 E0 9A 20 84 00 A9 83 01 03 80 00 7C 80 01 E4
80 03 48 01 02 00 01 20 00 01 26 81 82 91 92 93
94 95 96 97 98 91 92 93 94 95 96 97 98 91 92 93
94 95 96 97 98 91 92 93 94 95 96 97 98 80 82 31
32 33 34 35 36 37 38 31 32 33 34 35 36 37 38 31
32 33 34 35 36 37 38 31 32 33 34 35 36 37 38 41
42 43 44 45 46 47 48 41 42 43 44 45 46 47 48 41
42 43 44 45 46 47 48 41 42 43 44 45 46 47 48""".replaceAll("\n","").replaceAll(" ","").toLowerCase()

	String coerReferenceWithHeaderInfoExtension = normalizeHex """03 81 00 40 03 80 0F 54 68 69 73 20 69 73 20 61
20 42 53 4D 0D 0A C0 01 20 11 12 13 14 15 16 17
18 02 06 80 05 01 01 12 13 14 80 21 22 23 24 25
26 27 28 80 82 31 32 33 34 35 36 37 38 31 32 33
34 35 36 37 38 31 32 33 34 35 36 37 38 31 32 33
34 35 36 37 38 41 42 43 44 45 46 47 48 41 42 43
44 45 46 47 48 41 42 43 44 45 46 47 48 41 42 43
44 45 46 47 48"""

	String coerReferenceWithMultipleHeaderInfoExtension = normalizeHex """03 81 00 40 03 80 0F 54 68 69 73 20 69 73 20 61
20 42 53 4D 0D 0A C0 01 20 00 00 0A 35 23 77 2A
85 02 06 C0 05 01 01 22 33 44 81 88 80 03 00 80
00 00 00 00 00 00 00 00 04 83 00 00 00 00 00 00
00 00 00 80 00 00 01 01 00 80 01 01 00 01 00 80
80 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 80 80 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 80 80 00 00 00 00 00 00 00 80 80 82
00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
FF 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E"""

	String coerReferenceWithSha384Values = normalizeHex """03 81 01 40 03 80 0F 54 68 69 73 20 69 73 20 61
20 42 53 4D 0D 0A C0 01 20 00 00 0A 35 23 77 2A
85 02 06 C0 05 01 01 22 33 44 81 9A 80 03 00 82
08 FF FF FF FF FF FF FF FF 04 83 FF FF FF 00 00
00 00 00 00 80 00 00 01 01 00 80 01 01 00 01 00
80 82 31 80 FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF 80 80 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 80 80 00 00 00 00 00 00 00 82
81 91 84 FF FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
FF FF FF"""


	def "Verify coer with header info extension"(){
		when:
		Ieee1609Dot2Data d = new Ieee1609Dot2Data( Hex.decode(coerReferenceWithHeaderInfoExtension))
		then:
		Hex.toHexString(d.encoded) == coerReferenceWithHeaderInfoExtension

		when:
		d = new Ieee1609Dot2Data( Hex.decode(coerReferenceWithMultipleHeaderInfoExtension))
		then:
		Hex.toHexString(d.encoded) == coerReferenceWithMultipleHeaderInfoExtension

		when:
		d = new Ieee1609Dot2Data( Hex.decode(coerReferenceWithSha384Values))
		println d.toString()
		then:
		Hex.toHexString(d.encoded) == coerReferenceWithSha384Values
	}

	def "Verify coer reference data struct from IEEE 1609.2 2016 D 5.1.2"(){
		when:
		Ieee1609Dot2Data d = new Ieee1609Dot2Data( Hex.decode(fromDoc2016_1))
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
      signer=[digest=2122232425262728],
      signature=[ecdsaNistP256Signature=EcdsaP256[r=[compressedy0=3132333435363738313233343536373831323334353637383132333435363738], s=4142434445464748414243444546474841424344454647484142434445464748]]
    ]
  ]
]"""
		Hex.toHexString(d.encoded) == fromDoc2016_1

	}

	def "Verify coer reference data struct from IEEE 1609.2 2016 D 5.2.2"(){
		when:
		Ieee1609Dot2Data d = new Ieee1609Dot2Data( Hex.decode(fromDoc2016_2))
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
		Hex.toHexString(d.encoded) == fromDoc2016_2

	}

	def "Verify coer referenceDataStruct form P1609.2 2016 "(){
		when:
		Ieee1609Dot2Data d = new Ieee1609Dot2Data( Hex.decode(referenceDataStruct))
		then:
		Hex.toHexString(d.encoded) == referenceDataStruct

	}


	def "Verify that reference structure from D.5.2.2 of P1909.2_D12 is parsed and regenerated correctly"(){
		when:
		Ieee1609Dot2Data d = new Ieee1609Dot2Data( Hex.decode(referenceDataStruct))
		String s1 = d.toString()
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
		serializeToHex(d) == referenceDataStruct
		when:
		Ieee1609Dot2Data d2 = new Ieee1609Dot2Data(Hex.decode(serializeToHex(d)))
		then:
		s1 == d2.toString()
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
