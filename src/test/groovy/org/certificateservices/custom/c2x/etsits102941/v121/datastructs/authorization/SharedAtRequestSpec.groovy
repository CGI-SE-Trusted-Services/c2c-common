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
package org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.CertificateFormat
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.CertificateSubjectAttributes
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.*

/**
 * Unit tests for SharedAtRequest
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class SharedAtRequestSpec extends BaseStructSpec {

    HashedId8 eaId = new HashedId8(Hex.decode("0011223344556677"))
    byte[] keyTag = Hex.decode("00112233445566778899001122334455")
    CertificateSubjectAttributes requestedSubjectAttributes = genCertificateSubjectAttributes(null)

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        SharedAtRequest r = new SharedAtRequest(eaId, keyTag, CertificateFormat.TS103097C131, requestedSubjectAttributes)
        then:
        serializeToHex(r) == "00001122334455667700112233445566778899001122334455017c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5"
        when:
        SharedAtRequest r2 = deserializeFromHex(new SharedAtRequest(), "00001122334455667700112233445566778899001122334455017c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5")
        then:
        r2.getEaId() == eaId
        r2.getKeyTag() == keyTag
        r2.certificateFormat == CertificateFormat.TS103097C131
        r2.requestedSubjectAttributes == requestedSubjectAttributes
    }


    def "Verify that IllegalArgumentException is thrown if requested permissions have certIssuePermission Set"(){
        setup:
        PsidGroupPermissions perm1 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),null,null,new EndEntityType(true, true))
        PsidGroupPermissions perm2 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),2,3,new EndEntityType(false, true))

        when:
        new SharedAtRequest(eaId, keyTag, CertificateFormat.TS103097C131,  genCertificateSubjectAttributes(new SequenceOfPsidGroupPermissions([perm1, perm2])))
        then:
        def e = thrown IllegalArgumentException
        e.message == "Invalid requestedSubjectAttributes in SharedAtRequest, certIssuePermissions cannot be set."
    }

    def "Verify toString()"(){
        expect:
        new SharedAtRequest(eaId, keyTag, CertificateFormat.TS103097C131, requestedSubjectAttributes).toString() == """SharedAtRequest [
  eaId=[0011223344556677]
  keyTag=00112233445566778899001122334455
  certificateFormat=COERInteger [value=1]
  requestedSubjectAttributes=[
    id=[name=[SomeCertId]]
    validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
    assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
    appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
    certIssuePermissions=NONE
  ]
]"""

    }

    static CertificateSubjectAttributes genCertificateSubjectAttributes(SequenceOfPsidGroupPermissions certIssuePermissions = null){
        CertificateId id = new CertificateId(new Hostname("SomeCertId"))
        ValidityPeriod validityPeriod = new ValidityPeriod(new Time32(new Date(1452864033295L)), new Duration(Duration.DurationChoices.hours, 5))
        GeographicRegion region = new GeographicRegion(GeographicRegion.GeographicRegionChoices.identifiedRegion, new SequenceOfIdentifiedRegion(new IdentifiedRegion(IdentifiedRegion.IdentifiedRegionChoices.countryOnly, new CountryOnly(9))))
        SubjectAssurance assuranceLevel = new SubjectAssurance(3,2)
        byte[] sspData = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),30)
        ServiceSpecificPermissions ssp = new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, sspData)
        SequenceOfPsidSsp appPermissions = new SequenceOfPsidSsp([new PsidSsp(new Psid(101), ssp), new PsidSsp(new Psid(202), ssp)])
        return new CertificateSubjectAttributes(id,validityPeriod,region,assuranceLevel,
                appPermissions,certIssuePermissions)
    }
}
