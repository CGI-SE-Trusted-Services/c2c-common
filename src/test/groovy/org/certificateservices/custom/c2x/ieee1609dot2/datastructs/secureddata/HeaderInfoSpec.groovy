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
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Elevation
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Latitude
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Longitude
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfHashedId3
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmetricEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmetricEncryptionKey.SymmetricEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ThreeDLocation;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.MissingCrlIdentifier
import org.certificateservices.custom.c2x.ieee1609dot2.generator.BaseCertGeneratorSpec;
import org.junit.Ignore;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll

import java.security.KeyPair;

/**
 * Test for HeaderInfo
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class HeaderInfoSpec extends BaseCertGeneratorSpec {

	HashedId3 cracaid = new HashedId3(Hex.decode("010203040506070809101112"))
	CrlSeries crlSeries =new CrlSeries(100)
	byte[] k = COEREncodeHelper.padZerosToByteArray(Hex.decode("0100"),16);
	SymmetricEncryptionKey symmkey = new SymmetricEncryptionKey(SymmetricEncryptionKeyChoices.aes128Ccm,k)
	
	Psid psid = new Psid(64)
	Time64 generationTime = new Time64(BigInteger.valueOf(5000000L))
	Time64 expiryTime = new Time64(BigInteger.valueOf(6000000L)) 
	ThreeDLocation generationLocation = new ThreeDLocation(new Latitude(50),new Longitude(100),new Elevation(55))
	HashedId3 p2pcdLearningRequest = new HashedId3(Hex.decode("010203040506070809101112")) 
	MissingCrlIdentifier missingCrlIdentifier =  new MissingCrlIdentifier(cracaid,crlSeries)
	EncryptionKey encryptionKey = new EncryptionKey(symmkey)
	SequenceOfHashedId3 inlineP2pcdRequest = new SequenceOfHashedId3([new HashedId3(Hex.decode("ab1232")),new HashedId3(Hex.decode("ab1233"))])
	Certificate requestedCertificate = deserializeFromHex(new Certificate(),"80030081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")

	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		HeaderInfo hi1 = new HeaderInfo(psid,generationTime, expiryTime, generationLocation, p2pcdLearningRequest, missingCrlIdentifier, encryptionKey, inlineP2pcdRequest, requestedCertificate)
		then:
		hi1.hasExtension
		serializeToHex(hi1) == "fe014000000000004c4b4000000000005b8d80000000320000006400371011120010111200648180000000000000000000000000000001000206c0080102ab1232ab123382015180030081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
		when:
		HeaderInfo hi2 = deserializeFromHex(new HeaderInfo(), "fe014000000000004c4b4000000000005b8d80000000320000006400371011120010111200648180000000000000000000000000000001000206c0080102ab1232ab123382015180030081007f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e08101020103400102e08101050106c0e0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
		then:
		hi2.hasExtension
		hi2.getPsid() == psid
		hi2.getGenerationTime() == generationTime
		hi2.getExpiryTime() == expiryTime
		hi2.getGenerationLocation() == generationLocation
		hi2.getP2pcdLearningRequest() == p2pcdLearningRequest
		hi2.getMissingCrlIdentifier() == missingCrlIdentifier
		hi2.getEncryptionKey() == encryptionKey
		hi2.getInlineP2pcdRequest() == inlineP2pcdRequest
		hi2.getRequestedCertificate() == requestedCertificate
	
		when:
		HeaderInfo hi3 = new HeaderInfo(psid,null,null,null,null,null,null, null,null)
		then:
		serializeToHex(hi3) == "000140"
		when: 
		HeaderInfo hi4 = deserializeFromHex(new HeaderInfo(), "000140")
		then:
		hi4.hasExtension
		hi4.getPsid() == psid
		hi4.getGenerationTime() == null
		hi4.getExpiryTime() == null
		hi4.getGenerationLocation() == null
		hi4.getP2pcdLearningRequest() == null
		hi4.getMissingCrlIdentifier() == null
		hi4.getEncryptionKey() == null
		hi4.getInlineP2pcdRequest() == null
		hi4.getRequestedCertificate() == null
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new HeaderInfo(null,generationTime, expiryTime, generationLocation, p2pcdLearningRequest, missingCrlIdentifier, encryptionKey,inlineP2pcdRequest,requestedCertificate)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new HeaderInfo(psid,generationTime, expiryTime, generationLocation, p2pcdLearningRequest, missingCrlIdentifier, encryptionKey, inlineP2pcdRequest,requestedCertificate).toString() == """HeaderInfo [
  psid=[64(40)],
  generationTime=[timeStamp=Thu Jan 01 02:23:20 CET 2004 (5000000)],
  expiryTime=[timeStamp=Thu Jan 01 02:40:00 CET 2004 (6000000)],
  generationLocation=[latitude=50, longitude=100, elevation=55],
  p2pcdLearningRequest=[101112],
  missingCrlIdentifier=[cracaid=[101112], crlSeries=[100]],
  encryptionKey=[symmetric=[aes128Ccm=00000000000000000000000000000100]],
  inlineP2pcdRequest=[ab1232,ab1233],
  requestedCertificate=[
    version=3
    type=explicit
    issuer=[self=sha256]
    toBeSigned=[
      id=[name=[SomeCertId]]
      cracaId=[313233]
      crlSeries=[432]
      validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
      region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
      assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
      appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
      certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
      certRequestPermissions=[[subjectPermissions=[all], minChainDepth=5, chainDepthRange=6, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=7, chainDepthRange=8, eeType=[app=false, enroll=true]]]
      canRequestRollover=true
      encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]]
      verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]]
    ]
    signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
  ]
]"""
		new HeaderInfo(psid,null,null,null,null,null,null,null,null).toString() == """HeaderInfo [
  psid=[64(40)]
]"""
	}


	def coerReference = """FE 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 CA 5B 17 00 94 B6 2E 01 00 00 00 00 00
00 00 00 00 00 00 80 00 80 80 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 02 06 C0 05 01 01
00 00 00 48 00 03 01 80 00 00 00 00 00 00 00 00
00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 80 00 00 81 80 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00""".replaceAll(" ","")

	def "Verify that reference coer data parses header info correctly."(){
		when:
		HeaderInfo hi = deserializeFromHex(new HeaderInfo(), coerReference)
		then:
		hi.toString() == """HeaderInfo [
  psid=[0(0)],
  generationTime=[timeStamp=Thu Jan 01 01:00:00 CET 2004 (0)],
  expiryTime=[timeStamp=Thu Jan 01 01:00:00 CET 2004 (0)],
  generationLocation=[latitude=-900000000, longitude=-1799999999, elevation=0],
  p2pcdLearningRequest=[000000],
  missingCrlIdentifier=[cracaid=[000000], crlSeries=[0]],
  encryptionKey=[public_=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[xonly=0000000000000000000000000000000000000000000000000000000000000000]]]],
  inlineP2pcdRequest=[000000],
  requestedCertificate=[
    version=3
    type=implicit
    issuer=[sha256AndDigest=[0000000000000000]]
    toBeSigned=[
      id=[linkageData=[iCert=[0], linkage-value=[000000000000000000], group-linkage-value=NULL]]
      cracaId=[000000]
      crlSeries=[0]
      validityPeriod=[start=Time32 [timeStamp=Thu Jan 01 01:00:00 CET 2004 (0)], duration=Duration [0 microseconds]]
      region=NONE
      assuranceLevel=NONE
      appPermissions=NONE
      certIssuePermissions=NONE
      certRequestPermissions=NONE
      canRequestRollover=false
      encryptionKey=NONE
      verifyKeyIndicator=[reconstructionValue=[xonly=0000000000000000000000000000000000000000000000000000000000000000]]
    ]
    signature=NONE
  ]
]"""

	}

}
