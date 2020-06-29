package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment

import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.SharedAtRequestSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions

/**
 * TODO
 */
class EnrollmentResponseSpec extends BaseStructSpec {

    CertificateSubjectAttributes confirmedSubjectAttributes = SharedAtRequestSpec.genCertificateSubjectAttributes()

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        EnrollmentResponse r = new EnrollmentResponse(EnrollmentResponseCode.ok, confirmedSubjectAttributes)
        then:
        serializeToHex(r) == "40007c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5"
        when:
        EnrollmentResponse r2 = deserializeFromHex(new EnrollmentResponse(), "40007c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5")
        then:
        r2.getResponseCode() == EnrollmentResponseCode.ok
        r2.getConfirmedSubjectAttributes() == confirmedSubjectAttributes
        when:
        EnrollmentResponse r3 = new EnrollmentResponse(EnrollmentResponseCode.badcontenttype, null)
        then:
        serializeToHex(r3) == "0002"
        when:
        EnrollmentResponse r4 = deserializeFromHex(new EnrollmentResponse(), "0002")
        then:
        r4.getResponseCode() == EnrollmentResponseCode.badcontenttype
        r4.getConfirmedSubjectAttributes() == null
    }


    def "Verify that BadArgumentException is thrown if confirmed permissions have certIssuePermission Set"(){
        setup:
        PsidGroupPermissions perm1 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),null,null,new EndEntityType(true, true))
        PsidGroupPermissions perm2 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),2,3,new EndEntityType(false, true))

        when:
        new EnrollmentResponse(EnrollmentResponseCode.ok,  SharedAtRequestSpec.genCertificateSubjectAttributes(new SequenceOfPsidGroupPermissions([perm1, perm2])))
        then:
        def e = thrown IOException
        e.message == "Invalid confirmedSubjectAttributes in EnrollmentResponse, certIssuePermissions cannot be set."
    }

    def fullString = """EnrollmentResponse [
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

    def noConfirmedPermissionsString = """EnrollmentResponse [
  responseCode=badcontenttype
  confirmedSubjectAttributes=NONE
]"""

    def "Verify toString()"(){
        expect:
        new EnrollmentResponse(EnrollmentResponseCode.ok, confirmedSubjectAttributes).toString() == fullString
        new EnrollmentResponse(EnrollmentResponseCode.badcontenttype, null).toString() == noConfirmedPermissionsString
    }
}

