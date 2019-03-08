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
package org.certificateservices.custom.c2x.etsits103097.v131.cert

import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EcdsaP256Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GroupLinkageValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicEncryptionKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfIdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.LinkageData
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.ToBeSignedCertificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.VerificationKeyIndicator
import org.certificateservices.custom.c2x.ieee1609dot2.generator.BaseCertGeneratorSpec
import spock.lang.Specification

/**
 * Unit tests for EtsiTs103097Certificate
 */
class EtsiTs103097CertificateSpec extends BaseCertGeneratorSpec {
    CertificateId id = new CertificateId(new Hostname("SomeCertId"))
    ToBeSignedCertificate explicitToBeSigned = genToBeSignedCertificate(id)
    IssuerIdentifier issuerId = new IssuerIdentifier(HashAlgorithm.sha256)
    Signature signature = new Signature(Signature.SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(new EccP256CurvePoint(new BigInteger(123)), COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)))

    def "Verify that valid certificate generates a valid certificate"(){
        when:
        EtsiTs103097Certificate c = new EtsiTs103097Certificate(issuerId,explicitToBeSigned,signature)
        then:
        serializeToHex(c) == "800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        when:
        Certificate c2 = deserializeFromHex(new Certificate(), "800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5")
        then:
        c2.getVersion() == Certificate.CURRENT_VERSION
        c2.getType() == CertificateType.explicit
        c2.getIssuer() == issuerId
        c2.getToBeSigned() == explicitToBeSigned
        c2.getSignature() == signature
    }

    def "Verify that IllegalArgumentException is thrown if certificate id is linkageData"(){
        setup:
        IValue c = new IValue(5);
        LinkageValue lv = new LinkageValue("012345678".bytes)
        GroupLinkageValue gvl = new GroupLinkageValue("1234".bytes,"012345678".bytes)
        LinkageData ld1 = new LinkageData(c,lv,gvl)
        CertificateId id = new CertificateId(ld1)
        ToBeSignedCertificate toBeSigned = genToBeSignedCertificate(id)
        when:
        new EtsiTs103097Certificate(issuerId,toBeSigned,signature)
        then:
        def e = thrown IllegalArgumentException
        e.message == "Invalid id type in toBeSigned field of EtsiTs103097Certificate: linkageData"
    }

    def "Verify that IllegalArgumentException is thrown if certificate id is binaryId"(){
        setup:
        CertificateId id = new CertificateId("1234".getBytes())
        ToBeSignedCertificate toBeSigned = genToBeSignedCertificate(id)
        when:
        new EtsiTs103097Certificate(issuerId,toBeSigned,signature)
        then:
        def e = thrown IllegalArgumentException
        e.message == "Invalid id type in toBeSigned field of EtsiTs103097Certificate: binaryId"
    }

    def "Verify that IllegalArgumentException is thrown if certificate has certRequestPermissions set"(){
        setup:
        PsidGroupPermissions perm3 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),5,6,new EndEntityType(true, true))
        PsidGroupPermissions perm4 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),7,8,new EndEntityType(false, true))
        SequenceOfPsidGroupPermissions certReqPermissions = new SequenceOfPsidGroupPermissions([perm3,perm4])

        ToBeSignedCertificate toBeSigned = genToBeSignedCertificate(id,false, certReqPermissions)
        when:
        new EtsiTs103097Certificate(issuerId,toBeSigned,signature)
        then:
        def e = thrown IllegalArgumentException
        e.message == "Invalid toBeSigned field of EtsiTs103097Certificate, field certRequestPermissions cannot be set."
    }

    def "Verify that IllegalArgumentException is thrown if certificate has canRequestRollover set"(){
        setup:
        ToBeSignedCertificate toBeSigned = genToBeSignedCertificate(id,true)
        when:
        new EtsiTs103097Certificate(issuerId,toBeSigned,signature)
        then:
        def e = thrown IllegalArgumentException
        e.message == "Invalid toBeSigned field of EtsiTs103097Certificate, field canRequestRollover cannot be set."
    }


    def "Verify toString()"(){
        expect:
        new EtsiTs103097Certificate(issuerId,explicitToBeSigned,signature).toString() == """EtsiTs103097Certificate [
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
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]]
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]]
  ]
  signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
]"""
    }

    static ToBeSignedCertificate genToBeSignedCertificate(CertificateId id, boolean canRequestRollover=false, SequenceOfPsidGroupPermissions certRequestPermissions=null){
        byte[] sspData = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),30)
        ServiceSpecificPermissions ssp = new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, sspData)


        EccP256CurvePoint p1 = new EccP256CurvePoint(new BigInteger(123),new BigInteger(223))
        BasePublicEncryptionKey pubKey1 = new BasePublicEncryptionKey(BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, p1)

        EccP256CurvePoint p2 = new EccP256CurvePoint(new BigInteger(323),new BigInteger(423))
        PublicVerificationKey pvk = new PublicVerificationKey(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256, p2)

        PsidGroupPermissions perm1 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),null,null,new EndEntityType(true, true))
        PsidGroupPermissions perm2 = new PsidGroupPermissions(new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null),2,3,new EndEntityType(false, true))


        HashedId3 cracaId = new HashedId3("123".bytes)
        CrlSeries crlSeries  = new CrlSeries(432)
        ValidityPeriod validityPeriod = new ValidityPeriod(new Time32(new Date(1452864033295L)), new Duration(Duration.DurationChoices.hours, 5))
        GeographicRegion region = new GeographicRegion(GeographicRegion.GeographicRegionChoices.identifiedRegion, new SequenceOfIdentifiedRegion(new IdentifiedRegion(IdentifiedRegion.IdentifiedRegionChoices.countryOnly, new CountryOnly(9))))
        SubjectAssurance assuranceLevel = new SubjectAssurance(3,2)
        SequenceOfPsidSsp appPermissions = new SequenceOfPsidSsp([new PsidSsp(new Psid(101), ssp), new PsidSsp(new Psid(202), ssp)])
        SequenceOfPsidGroupPermissions certIssuePermissions = new SequenceOfPsidGroupPermissions([perm1, perm2])

        PublicEncryptionKey encryptionKey = new PublicEncryptionKey(SymmAlgorithm.aes128Ccm,pubKey1)
        VerificationKeyIndicator verifyKeyIndicator_vk = new VerificationKeyIndicator(pvk)

        return new ToBeSignedCertificate(id, cracaId, crlSeries, validityPeriod, region, assuranceLevel, appPermissions, certIssuePermissions, certRequestPermissions, canRequestRollover, encryptionKey,  verifyKeyIndicator_vk)
    }
}
