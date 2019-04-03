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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.asn1.coer.COERIA5String
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequestSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.SharedAtRequestSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateFormat
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions

/**
 * Unit tests for InnerEcRequest
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class InnerEcRequestSpec extends BaseStructSpec {

    byte[] itsAid = "abc123".getBytes("UTF-8")
    PublicKeys publicKeys = InnerAtRequestSpec.genPublicKeys()
    CertificateSubjectAttributes requestedSubjectAttributes = SharedAtRequestSpec.genCertificateSubjectAttributes()

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        InnerEcRequest r = new InnerEcRequest(itsAid, CertificateFormat.TS103097C131, publicKeys, requestedSubjectAttributes)
        then:
        Hex.toHexString(r.encoded) == "000661626331323301808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b7c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5"
        when:
        InnerEcRequest r2 = new InnerEcRequest(Hex.decode("000661626331323301808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b7c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5"))
        then:
        r2.getItsId() == itsAid
        r2.getCertificateFormat() == CertificateFormat.TS103097C131
        r2.getPublicKeys() == publicKeys
        r2.getRequestedSubjectAttributes() == requestedSubjectAttributes
    }


    def "Verify that IllegalArgumentException is thrown if requested permissions have certIssuePermission Set"(){
        setup:
        PsidGroupPermissions perm1 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),null,null,new EndEntityType(true, true))
        PsidGroupPermissions perm2 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),2,3,new EndEntityType(false, true))

        when:
        new InnerEcRequest(itsAid, CertificateFormat.TS103097C131, publicKeys, SharedAtRequestSpec.genCertificateSubjectAttributes(new SequenceOfPsidGroupPermissions([perm1, perm2])))
        then:
        def e = thrown IllegalArgumentException
        e.message == "Invalid requestedSubjectAttributes in InnerEcRequest, certIssuePermissions cannot be set."
    }

    def "Verify toString()"(){
        expect:
        new InnerEcRequest(itsAid, CertificateFormat.TS103097C131, publicKeys, requestedSubjectAttributes).toString() == """InnerEcRequest [
  itsId=616263313233
  certificateFormat=COERInteger [value=1]
  publicKeys=[verificationKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]],encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[xonly=000000000000000000000000000000000000000000000000000000000000007b]]]]
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
}
