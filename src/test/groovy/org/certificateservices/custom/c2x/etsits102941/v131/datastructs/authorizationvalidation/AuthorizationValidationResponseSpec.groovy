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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.SharedAtRequestSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions

/**
 * Unit tests for AuthorizationValidationResponse.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class AuthorizationValidationResponseSpec extends BaseStructSpec {

    byte[] requestHash = Hex.decode("00112233445566778899001122334455")
    CertificateSubjectAttributes confirmedSubjectAttributes = SharedAtRequestSpec.genCertificateSubjectAttributes()

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        AuthorizationValidationResponse r = new AuthorizationValidationResponse(requestHash, AuthorizationValidationResponseCode.ok, confirmedSubjectAttributes)
        then:
        serializeToHex(r) == "4000112233445566778899001122334455007c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5"
        when:
        AuthorizationValidationResponse r2 = deserializeFromHex(new AuthorizationValidationResponse(), "4000112233445566778899001122334455007c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5")
        then:
        r2.getRequestHash() == requestHash
        r2.getResponseCode() == AuthorizationValidationResponseCode.ok
        r2.getConfirmedSubjectAttributes() == confirmedSubjectAttributes
        when:
        AuthorizationValidationResponse r3 = new AuthorizationValidationResponse(requestHash, AuthorizationValidationResponseCode.badcontenttype, null)
        then:
        serializeToHex(r3) == "000011223344556677889900112233445502"
        when:
        AuthorizationValidationResponse r4 = deserializeFromHex(new AuthorizationValidationResponse(), "000011223344556677889900112233445502")
        then:
        r4.getRequestHash() == requestHash
        r4.getResponseCode() == AuthorizationValidationResponseCode.badcontenttype
        r4.getConfirmedSubjectAttributes() == null
    }


    def "Verify that IllegalArgumentException is thrown if confirmed permissions have certIssuePermission Set"(){
        setup:
        PsidGroupPermissions perm1 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),null,null,new EndEntityType(true, true))
        PsidGroupPermissions perm2 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),2,3,new EndEntityType(false, true))

        when:
        new AuthorizationValidationResponse(requestHash, AuthorizationValidationResponseCode.ok,  SharedAtRequestSpec.genCertificateSubjectAttributes(new SequenceOfPsidGroupPermissions([perm1, perm2])))
        then:
        def e = thrown IllegalArgumentException
        e.message == "Invalid confirmedSubjectAttributes in AuthorizationValidationResponse, certIssuePermissions cannot be set."
    }

    def fullString = """AuthorizationValidationResponse [
  requestHash=00112233445566778899001122334455
  responseCode=ok
  confirmedSubjectAttributes=[
    id=[name=[SomeCertId]]
    validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
    region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
    assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
    appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
    certIssuePermissions=NONE
  ]
]"""

    def noConfirmedPermissionsString = """AuthorizationValidationResponse [
  requestHash=00112233445566778899001122334455
  responseCode=badcontenttype
  confirmedSubjectAttributes=NONE
]"""

    def "Verify toString()"(){
        expect:
        new AuthorizationValidationResponse(requestHash, AuthorizationValidationResponseCode.ok, confirmedSubjectAttributes).toString() == fullString
        new AuthorizationValidationResponse(requestHash, AuthorizationValidationResponseCode.badcontenttype, null).toString() == noConfirmedPermissionsString

    }
}
