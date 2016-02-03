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
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Elevation
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Latitude
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Longitude
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SymmetricEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SymmetricEncryptionKey.SymmetricEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ThreeDLocation;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.junit.Ignore;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for HeaderInfo
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class HeaderInfoSpec extends BaseStructSpec {

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
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		HeaderInfo hi1 = new HeaderInfo(psid,generationTime, expiryTime, generationLocation, p2pcdLearningRequest, missingCrlIdentifier, encryptionKey)
		then:
		hi1.hasExtension
		serializeToHex(hi1) == "7e014000000000004c4b4000000000005b8d8000000032000000640037101112001011120064818000000000000000000000000000000100"
		when:
		HeaderInfo hi2 = deserializeFromHex(new HeaderInfo(), "7e014000000000004c4b4000000000005b8d8000000032000000640037101112001011120064818000000000000000000000000000000100")
		then:
		hi2.hasExtension
		hi2.getPsid() == psid
		hi2.getGenerationTime() == generationTime
		hi2.getExpiryTime() == expiryTime
		hi2.getGenerationLocation() == generationLocation
		hi2.getP2pcdLearningRequest() == p2pcdLearningRequest
		hi2.getMissingCrlIdentifier() == missingCrlIdentifier
		hi2.getEncryptionKey() == encryptionKey 
	
		when:
		HeaderInfo hi3 = new HeaderInfo(psid,null,null,null,null,null,null)
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
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new HeaderInfo(null,generationTime, expiryTime, generationLocation, p2pcdLearningRequest, missingCrlIdentifier, encryptionKey)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new HeaderInfo(psid,generationTime, expiryTime, generationLocation, p2pcdLearningRequest, missingCrlIdentifier, encryptionKey).toString() == """HeaderInfo [
  psid=[64(40)],
  generationTime=[timeStamp=Thu Jan 01 01:00:05 CET 2004 (5000000)],
  expiryTime=[timeStamp=Thu Jan 01 01:00:06 CET 2004 (6000000)],
  generationLocation=[latitude=50, longitude=100, elevation=55],
  p2pcdLearningRequest=[101112],
  missingCrlIdentifier=[cracaid=[101112], crlSeries=[100]],
  encryptionKey=[symmetric=[aes128Ccm=00000000000000000000000000000100]]
]"""
		new HeaderInfo(psid,null,null,null,null,null,null).toString() == """HeaderInfo [
  psid=[64(40)]
]"""
	}
	

}
