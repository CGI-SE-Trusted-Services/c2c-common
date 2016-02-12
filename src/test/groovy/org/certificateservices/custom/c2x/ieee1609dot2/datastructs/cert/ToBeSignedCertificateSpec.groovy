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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert

import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey.BasePublicEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfIdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion.GeographicRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.ToBeSignedCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for ToBeSignedCertificate
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class ToBeSignedCertificateSpec extends BaseStructSpec {

	byte[] sspData = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),30)
	ServiceSpecificPermissions ssp = new ServiceSpecificPermissions(ServiceSpecificPermissionsChoices.opaque, sspData)
	
	
	EccP256CurvePoint p1 = new EccP256CurvePoint(new BigInteger(123),new BigInteger(222))
	BasePublicEncryptionKey pubKey1 = new BasePublicEncryptionKey(BasePublicEncryptionKeyChoices.ecdsaNistP256, p1)
	
	EccP256CurvePoint p2 = new EccP256CurvePoint(new BigInteger(323),new BigInteger(422))
	
	PsidGroupPermissions perm1 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.all, null),null,null,new EndEntityType(true, true))
	PsidGroupPermissions perm2 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.all, null),2,3,new EndEntityType(false, true))
	
	PsidGroupPermissions perm3 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.all, null),5,6,new EndEntityType(true, true))
	PsidGroupPermissions perm4 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissionsChoices.all, null),7,8,new EndEntityType(false, true))
	
	CertificateId id = new CertificateId(new Hostname("SomeCertId"))
	HashedId3 cracaId = new HashedId3("123".bytes)
	CrlSeries crlSeries  = new CrlSeries(432)
	ValidityPeriod validityPeriod = new ValidityPeriod(new Time32(new Date(1452864033295L)), new Duration(DurationChoices.hours, 5))
	GeographicRegion region = new GeographicRegion(GeographicRegionChoices.identifiedRegion, new SequenceOfIdentifiedRegion(new IdentifiedRegion(IdentifiedRegionChoices.countryOnly, new CountryOnly(9))))
	SubjectAssurance assuranceLevel = new SubjectAssurance(3,2)
	SequenceOfPsidSsp appPermissions = new SequenceOfPsidSsp([new PsidSsp(new Psid(101), ssp),new PsidSsp(new Psid(202), ssp)])
	SequenceOfPsidGroupPermissions certIssuePermissions = new SequenceOfPsidGroupPermissions([perm1,perm2])
	SequenceOfPsidGroupPermissions certRequestPermissions = new SequenceOfPsidGroupPermissions([perm3,perm4])
	boolean canRequestRollover = true
	PublicEncryptionKey encryptionKey = new PublicEncryptionKey(SymmAlgorithm.aes128Ccm,pubKey1)
	VerificationKeyIndicator verifyKeyIndicator = new VerificationKeyIndicator(p2)
	

	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		
		ToBeSignedCertificate c = new ToBeSignedCertificate(id,cracaId,crlSeries,validityPeriod,region,assuranceLevel,
			appPermissions,certIssuePermissions,certRequestPermissions,canRequestRollover,encryptionKey,verifyKeyIndicator)
		then:
		
		serializeToHex(c) == "7f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000de8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a6"
		when:
		ToBeSignedCertificate c2 = deserializeFromHex(new ToBeSignedCertificate(), "7f810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000de8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a6")
		then:
		c2.getId() == id
		c2.getCracaId() == cracaId
		c2.getCrlSeries() == crlSeries
		c2.getValidityPeriod() == validityPeriod
		c2.getRegion() == region
		c2.getAssuranceLevel() == assuranceLevel
		c2.getAppPermissions() == appPermissions
		c2.getCertIssuePermissions() == certIssuePermissions
		c2.getCertRequestPermissions() == certRequestPermissions
		c2.isCanRequestRollover() == canRequestRollover
		c2.getEncryptionKey() == encryptionKey
		c2.getVerifyKeyIndicator() == verifyKeyIndicator
		
		when:
		ToBeSignedCertificate c3 = new ToBeSignedCertificate(id,cracaId,crlSeries,validityPeriod,region,assuranceLevel,
			appPermissions,certIssuePermissions,certRequestPermissions,false,encryptionKey,verifyKeyIndicator)
		then:
		serializeToHex(c3) == "7d810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000de8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a6"
		when:
		ToBeSignedCertificate c4 = deserializeFromHex(new ToBeSignedCertificate(), "7d810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501020081c0c08101020103400102c08101050106c0c0810107010840008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000de8184000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a6")
		then:
		c4.getId() == id
		c4.getCracaId() == cracaId
		c4.getCrlSeries() == crlSeries
		c4.getValidityPeriod() == validityPeriod
		c4.getRegion() == region
		c4.getAssuranceLevel() == assuranceLevel
		c4.getAppPermissions() == appPermissions
		c4.getCertIssuePermissions() == certIssuePermissions
		c4.getCertRequestPermissions() == certRequestPermissions
		c4.isCanRequestRollover() == false
		c4.getEncryptionKey() == encryptionKey
		c4.getVerifyKeyIndicator() == verifyKeyIndicator
		
	}
	
	def "Verify that encode and decode to byte array is correct"(){
		when:
	    ToBeSignedCertificate tbs1 = new ToBeSignedCertificate(id,cracaId,crlSeries,validityPeriod,region,assuranceLevel,
			appPermissions,certIssuePermissions,certRequestPermissions,canRequestRollover,encryptionKey,verifyKeyIndicator)
		ToBeSignedCertificate tbs2 = new ToBeSignedCertificate(tbs1.encoded)
		then:
		tbs1 == tbs2
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
	
		when:
		new ToBeSignedCertificate(null,cracaId,crlSeries,validityPeriod,region,assuranceLevel,
			appPermissions,certIssuePermissions,certRequestPermissions,canRequestRollover,encryptionKey,verifyKeyIndicator)
		then:
		thrown IllegalArgumentException
		when:
		new ToBeSignedCertificate(id,null,crlSeries,validityPeriod,region,assuranceLevel,
		appPermissions,certIssuePermissions,certRequestPermissions,canRequestRollover,encryptionKey,verifyKeyIndicator)
		then:
		thrown IllegalArgumentException
		when:
		new ToBeSignedCertificate(id,cracaId,null,validityPeriod,region,assuranceLevel,
		appPermissions,certIssuePermissions,certRequestPermissions,canRequestRollover,encryptionKey,verifyKeyIndicator)
		then:
		thrown IllegalArgumentException
		when:
		new ToBeSignedCertificate(id,cracaId,crlSeries,null,region,assuranceLevel,
		appPermissions,certIssuePermissions,certRequestPermissions,canRequestRollover,encryptionKey,verifyKeyIndicator)
		then:
		thrown IllegalArgumentException
		when:
		new ToBeSignedCertificate(id,cracaId,crlSeries,validityPeriod,region,assuranceLevel,
		appPermissions,certIssuePermissions,certRequestPermissions,canRequestRollover,encryptionKey,null)
		then:
		thrown IllegalArgumentException
	} 
	
	def "Verify that IllegalArgumentException is thrown if none of required premissions doesn't exists"(){
		
			when:
			new ToBeSignedCertificate(id,cracaId,crlSeries,validityPeriod,region,assuranceLevel,
				null,null,null,canRequestRollover,encryptionKey,verifyKeyIndicator)
			then:
			thrown IllegalArgumentException
			when: // Verify that no exception is thrown if one of the is set.
			new ToBeSignedCertificate(id,cracaId,crlSeries,validityPeriod,region,assuranceLevel,
				appPermissions,null,null,canRequestRollover,encryptionKey,verifyKeyIndicator)
			new ToBeSignedCertificate(id,cracaId,crlSeries,validityPeriod,region,assuranceLevel,
				null,certIssuePermissions,null,canRequestRollover,encryptionKey,verifyKeyIndicator)
			new ToBeSignedCertificate(id,cracaId,crlSeries,validityPeriod,region,assuranceLevel,
				null,null,certRequestPermissions,canRequestRollover,encryptionKey,verifyKeyIndicator)
			then:
			true
		}
	
	def String fullString =
"""ToBeSignedCertificate [
  id=[name=[SomeCertId]]
  cracaId=[313233]
  crlSeries=[432]
  validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
  region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
  assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
  appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
  certIssuePermissions=[[appPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[appPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
  certRequestPermissions=[[appPermissions=[all], minChainDepth=5, chainDepthRange=6, eeType=[app=true, enroll=true]],[appPermissions=[all], minChainDepth=7, chainDepthRange=8, eeType=[app=false, enroll=true]]]
  canRequestRollover=true
  encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000de]]]]
  verifyKeyIndicator=[reconstructionValue=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a6]]]
]"""

  def String withAppPermsOnly =
"""ToBeSignedCertificate [
  id=[name=[SomeCertId]]
  cracaId=[313233]
  crlSeries=[432]
  validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
  region=NONE
  assuranceLevel=NONE
  appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
  certIssuePermissions=NONE
  certRequestPermissions=NONE
  canRequestRollover=false
  encryptionKey=NONE
  verifyKeyIndicator=[reconstructionValue=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a6]]]
]"""
def String withcertRequestPermissionsOnly =
"""ToBeSignedCertificate [
  id=[name=[SomeCertId]]
  cracaId=[313233]
  crlSeries=[432]
  validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
  region=NONE
  assuranceLevel=NONE
  appPermissions=NONE
  certIssuePermissions=NONE
  certRequestPermissions=[[appPermissions=[all], minChainDepth=5, chainDepthRange=6, eeType=[app=true, enroll=true]],[appPermissions=[all], minChainDepth=7, chainDepthRange=8, eeType=[app=false, enroll=true]]]
  canRequestRollover=false
  encryptionKey=NONE
  verifyKeyIndicator=[reconstructionValue=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a6]]]
]"""

	def "Verify toString"(){
		expect:
		 new ToBeSignedCertificate(id,cracaId,crlSeries,validityPeriod,region,assuranceLevel,
			appPermissions,certIssuePermissions,certRequestPermissions,canRequestRollover,encryptionKey,verifyKeyIndicator).toString() == fullString
		new ToBeSignedCertificate(id,cracaId,crlSeries,validityPeriod,null,null,
			appPermissions,null,null,false,null,verifyKeyIndicator).toString() == withAppPermsOnly
		new ToBeSignedCertificate(id,cracaId,crlSeries,validityPeriod,null,null,
			null,null,certRequestPermissions,false,null,verifyKeyIndicator).toString() == withcertRequestPermissionsOnly
	}
	

}
