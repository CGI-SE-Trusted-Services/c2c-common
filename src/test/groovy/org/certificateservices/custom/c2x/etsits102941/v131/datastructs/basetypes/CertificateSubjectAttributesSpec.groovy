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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes

import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.*

/**
 * Unit tests for CertificateSubjectAttribute
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CertificateSubjectAttributesSpec extends BaseStructSpec {

    byte[] sspData = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),30)
    ServiceSpecificPermissions ssp = new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, sspData)


    EccP256CurvePoint p1 = new EccP256CurvePoint(new BigInteger(123),new BigInteger(222))
    BasePublicEncryptionKey pubKey1 = new BasePublicEncryptionKey(BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, p1)

    EccP256CurvePoint p2 = new EccP256CurvePoint(new BigInteger(323),new BigInteger(422))

    PsidGroupPermissions perm1 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),null,null,new EndEntityType(true, true))
    PsidGroupPermissions perm2 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),2,3,new EndEntityType(false, true))

    PsidGroupPermissions perm3 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),5,6,new EndEntityType(true, true))
    PsidGroupPermissions perm4 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),7,8,new EndEntityType(false, true))

    CertificateId id = new CertificateId(new Hostname("SomeCertId"))
    HashedId3 cracaId = new HashedId3("123".bytes)
    CrlSeries crlSeries  = new CrlSeries(432)
    ValidityPeriod validityPeriod = new ValidityPeriod(new Time32(new Date(1452864033295L)), new Duration(Duration.DurationChoices.hours, 5))
    GeographicRegion region = new GeographicRegion(GeographicRegion.GeographicRegionChoices.identifiedRegion, new SequenceOfIdentifiedRegion(new IdentifiedRegion(IdentifiedRegion.IdentifiedRegionChoices.countryOnly, new CountryOnly(9))))
    SubjectAssurance assuranceLevel = new SubjectAssurance(3,2)
    SequenceOfPsidSsp appPermissions = new SequenceOfPsidSsp([new PsidSsp(new Psid(101), ssp), new PsidSsp(new Psid(202), ssp)])
    SequenceOfPsidGroupPermissions certIssuePermissions = new SequenceOfPsidGroupPermissions([perm1, perm2])
    SequenceOfPsidGroupPermissions certRequestPermissions = new SequenceOfPsidGroupPermissions([perm3,perm4])
    boolean canRequestRollover = true
    PublicEncryptionKey encryptionKey = new PublicEncryptionKey(SymmAlgorithm.aes128Ccm,pubKey1)
    VerificationKeyIndicator verifyKeyIndicator = new VerificationKeyIndicator(p2)

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:

        CertificateSubjectAttributes c = new CertificateSubjectAttributes(id,validityPeriod,region,assuranceLevel,
                appPermissions,certIssuePermissions)
        then:

        serializeToHex(c) == "7e810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340"
        when:
        CertificateSubjectAttributes c2 = deserializeFromHex(new CertificateSubjectAttributes(), "7e810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340")
        then:
        c2.getId() == id
        c2.getValidityPeriod() == validityPeriod
        c2.getRegion() == region
        c2.getAssuranceLevel() == assuranceLevel
        c2.getAppPermissions() == appPermissions
        c2.getCertIssuePermissions() == certIssuePermissions

        when:
        CertificateSubjectAttributes c3 = new CertificateSubjectAttributes(null,null,null,null,
                appPermissions,null)
        then:
        serializeToHex(c3) == "040102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5"
        when:
        CertificateSubjectAttributes c4 = deserializeFromHex(new CertificateSubjectAttributes(), "040102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5")
        then:
        c4.getId() == null
        c4.getValidityPeriod() == null
        c4.getRegion() == null
        c4.getAssuranceLevel() == null
        c4.getAppPermissions() == appPermissions
        c4.getCertIssuePermissions() == null

        when:
        CertificateSubjectAttributes c5 = new CertificateSubjectAttributes(null,null,null,null,
                null,certIssuePermissions)
        then:
        serializeToHex(c5) == "0201022081c0e0810102010340"
        when:
        CertificateSubjectAttributes c6 = deserializeFromHex(new CertificateSubjectAttributes(), "0201022081c0e0810102010340")
        then:
        c6.getId() == null
        c6.getValidityPeriod() == null
        c6.getRegion() == null
        c6.getAssuranceLevel() == null
        c6.getAppPermissions() == null
        c6.getCertIssuePermissions() == certIssuePermissions
    }


    def "Verify that BadArgumentException is thrown if none of required permissions doesn't exists"(){

        when:
        new CertificateSubjectAttributes(id,validityPeriod,region,assuranceLevel,
                null,null)
        then:
        def e = thrown IOException
        e.message == "Invalid CertificateSubjectAttributes one of appPermissions, certIssuePermissions must be present"
        when: // Verify that no exception is thrown if one of the is set.
        new CertificateSubjectAttributes(id,validityPeriod,region,assuranceLevel,
                appPermissions,null)
        new CertificateSubjectAttributes(id,validityPeriod,region,assuranceLevel,
                null,certIssuePermissions)
        then:
        true
    }

    def String fullString =
            """CertificateSubjectAttributes [
  id=[name=[SomeCertId]]
  validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
  region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
  assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
  appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
  certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
]"""

    def String withAppPermsOnly =
            """CertificateSubjectAttributes [
  id=[name=[SomeCertId]]
  validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
  region=NONE
  assuranceLevel=NONE
  appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
  certIssuePermissions=NONE
]"""

    def String withCertIssuePermissionsOnly =
            """CertificateSubjectAttributes [
  id=[name=[SomeCertId]]
  validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
  region=NONE
  assuranceLevel=NONE
  appPermissions=NONE
  certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
]"""


    def "Verify toString"(){
        expect:
        new CertificateSubjectAttributes(id,validityPeriod,region,assuranceLevel,
                appPermissions,certIssuePermissions).toString() == fullString
        new CertificateSubjectAttributes(id,validityPeriod,null,null,
                appPermissions,null).toString() == withAppPermsOnly
        new CertificateSubjectAttributes(id,validityPeriod,null,null,
                null,certIssuePermissions).toString() == withCertIssuePermissionsOnly

        new CertificateSubjectAttributes(null,null,null,null,
                appPermissions,null).toString() == """CertificateSubjectAttributes [
  id=NONE
  validityPeriod=NONE
  region=NONE
  assuranceLevel=NONE
  appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
  certIssuePermissions=NONE
]"""
    }

}
