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
package org.certificateservices.custom.c2x.ieee1609dot2.validator

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorizationTicketGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.validator.ETSI103097CertificateValidator
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BitmapSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BitmapSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CircularRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryAndRegions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryAndSubregions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Latitude
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Longitude
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.RegionAndSubregions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfIdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfOctetString
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfRegionAndSubregions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfUint16
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfUint8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.TwoDLocation
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint16
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions
import spock.lang.Specification
import spock.lang.Unroll

import java.security.KeyPair
import java.security.PrivateKey
import java.text.SimpleDateFormat

/**
 * Unit tests for BaseCertificateValidator
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class BaseCertificateValidatorSpec extends Specification {

    ETSI103097CertificateValidator certificateValidator
    static Ieee1609Dot2CryptoManager cryptoManager

    def setupSpec(){
        initCryptoManager()
    }

    static void initCryptoManager(){
        cryptoManager = new DefaultCryptoManager()
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
    }

    def setup(){
        certificateValidator = new ETSI103097CertificateValidator(cryptoManager)
    }

    def "Verify that a valid certificate chain doesn't throw any InvalidCertificateException"(){
        when:
        def chain = genValidChain()
        certificateValidator.verifyAndValidate(chain, toDate("2019-08-01 15:01:02"), GeographicRegion.generateRegionForCountrys([14]),
        new EndEntityType(false,true), true)
        then:
        true
        //BasePermissionValidatorSpec.printChain(chain)
    }

    @Unroll
    def "Verify that cert of type #type with invalid signature throws InvalidCertificateException"(){
        setup:
        def chain = genInvalidSignatureChain(type)
        when:
        certificateValidator.verifyAndValidate(chain, toDate("2019-08-01 15:01:02"), GeographicRegion.generateRegionForCountrys([14]),
                new EndEntityType(false,true), true)
        then:
        def e = thrown InvalidCertificateException
        e.message == expectedMessage

        where:
        type           | expectedMessage
        "endentity"    | "Error verifying signature of certificate in position 0 in certificate chain."
        "subca"        | "Error verifying signature of certificate in position 1 in certificate chain."
        "rootca"       | "Error verifying self signed certificate signature."
    }

    def "Verify that sub ca is not verified if entireChain is false"(){
        setup:
        def chain = genInvalidSignatureChain("subca")
        when:
        certificateValidator.verifyAndValidate(chain, toDate("2019-08-01 15:01:02"), GeographicRegion.generateRegionForCountrys([14]),
                new EndEntityType(false,true), false)
        then:
        true
    }

    @Unroll
    def "Verify that cert of type #type that have expired throws InvalidCertificateException"(){
        setup:
        def chain = genExpiredChain(type)
        when:
        certificateValidator.verifyAndValidate(chain, toDate("2019-08-01 15:01:02"), GeographicRegion.generateRegionForCountrys([14]),
                new EndEntityType(false,true), true)
        then:
        def e = thrown InvalidCertificateException
        e.message == expectedMessage

        where:
        type           | expectedMessage
        "endentity"    | "Expired certificate exists in chain."
        "subca"        | "Expired certificate exists in chain."
        "rootca"       | "Expired certificate exists in chain."
    }

    def "Verify that sub ca is not checked for time validity if entireChain is false"(){
        setup:
        def chain = genExpiredChain("subca")
        when:
        certificateValidator.verifyAndValidate(chain, toDate("2019-08-01 15:01:02"), GeographicRegion.generateRegionForCountrys([14]),
                new EndEntityType(false,true), false)
        then:
        true
    }

    @Unroll
    def "Verify that cert of type #type that have invalid region throws InvalidCertificateException"(){
        setup:
        def chain = genInvalidRegion(type)
        when:
        certificateValidator.verifyAndValidate(chain, toDate("2019-08-01 15:01:02"), GeographicRegion.generateRegionForCountrys([14]),
                new EndEntityType(false,true), true)
        then:
        def e = thrown InvalidCertificateException
        e.message == expectedMessage

        where:
        type           | expectedMessage
        "endentity"    | "Invalid set of countryOnly ids in certificate."
        "subca"        | "Invalid set of countryOnly ids in certificate."
        "rootca"       | "Invalid set of countryOnly ids in certificate."
    }

    def "Verify region always InvalidCertificateException if any region is wrong in chain even though entireChain is fails"(){
        setup:
        def chain = genInvalidRegion("subca")
        when:
        certificateValidator.verifyAndValidate(chain, toDate("2019-08-01 15:01:02"), GeographicRegion.generateRegionForCountrys([14]),
                new EndEntityType(false,true), false)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid set of countryOnly ids in certificate."
    }

    @Unroll
    def "Verify that cert of type #type that have invalid permissions throws InvalidCertificateException"(){
        setup:
        def chain = genInvalidPermissions(type)
        when:
        certificateValidator.verifyAndValidate(chain, toDate("2019-08-01 15:01:02"), GeographicRegion.generateRegionForCountrys([14]),
                new EndEntityType(false,true), true)
        then:
        def e = thrown InvalidCertificateException
        e.message == expectedMessage

        where:
        type           | expectedMessage
        "endentity"    | "Invalid PsidGroupPermissions for PSID 623, No matching PsidGroupPermissions found in issuer certificate."
        "subca"        | "Invalid PsidGroupPermissions for PSID 623, No matching PsidGroupPermissions found in issuer certificate."
    }

    def "Verify that sub ca is not checked for permissions if entireChain is false"(){
        setup:
        def chain = genInvalidPermissions("subca")
        when:
        certificateValidator.verifyAndValidate(chain, toDate("2019-08-01 15:01:02"), GeographicRegion.generateRegionForCountrys([14]),
                new EndEntityType(false,true), false)
        then:
        true
    }


    static Certificate[] genValidChain(){
        return genCertChain([
                [type: "ec",
                 name: "Test EC",
                 startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "hours",
                 countries: [12,14],
                 appPermissions: [[psid: 623, bitmapSsp: "01C0"]]
                ],
                [type: "subca",
                 name: "Test EA",
                 startTime: "2019-07-01 14:01:02", duration: 1, durationUnit: "years",
                 countries: [8,12,14,16],
                 appPermissions: [[psid: 623, bitmapSsp: "010E"]],
                 certIssuePermissions: [[subjectPermissions: [
                         [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                         [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                         [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                         [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                         [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                         [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                         [psid: 141, sspValue: "00", sspBitmask: "FF"],
                         [psid: 623, sspValue: "01C0", sspBitmask: "FF3F"],
                 ],
                                         minChainDepth: 1,
                                         chainDepthRange: 0,
                                         endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 startTime: "2019-06-01 14:01:02", duration: 2, durationUnit: "years",
                 countries: null,
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [[subjectPermissions: [
                         [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                         [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                         [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                         [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                         [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                         [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                         [psid: 141, sspValue: "00", sspBitmask: "FF"],
                         [psid: 623, sspValue: "01FE", sspBitmask: "FF01"],
                 ],
                                         minChainDepth: 2,
                                         chainDepthRange: 0,
                                         endEntityType: [app: true, enroll: true]]
                 ]
                ]
        ])
    }

    static Certificate[] genInvalidSignatureChain(String invalidCert){
        if(invalidCert == "rootca"){
            return genCertChain([
                    [type: "rootca",
                     name: "Test Rootca",
                     badsignature: (invalidCert == "rootca"),
                     startTime: "2019-06-01 14:01:02", duration: 2, durationUnit: "years",
                     countries: null,
                     appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                     certIssuePermissions: [[subjectPermissions: [
                             [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                             [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                             [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                             [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                             [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                             [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                             [psid: 141, sspValue: "00", sspBitmask: "FF"],
                             [psid: 623, sspValue: "01FE", sspBitmask: "FF01"],
                     ],
                                             minChainDepth: 2,
                                             chainDepthRange: 0,
                                             endEntityType: [app: true, enroll: true]]
                     ]
                    ]
            ])
        }
        return genCertChain([
                [type: "ec",
                 name: "Test EC",
                 badsignature: (invalidCert == "endentity"),
                 startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "hours",
                 countries: [12,14],
                 appPermissions: [[psid: 623, bitmapSsp: "01C0"]]
                ],
                [type: "subca",
                 name: "Test EA",
                 badsignature: (invalidCert == "subca"),
                 startTime: "2019-07-01 14:01:02", duration: 1, durationUnit: "years",
                 countries: [8,12,14,16],
                 appPermissions: [[psid: 623, bitmapSsp: "010E"]],
                 certIssuePermissions: [[subjectPermissions: [
                         [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                         [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                         [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                         [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                         [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                         [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                         [psid: 141, sspValue: "00", sspBitmask: "FF"],
                         [psid: 623, sspValue: "01C0", sspBitmask: "FF3F"],
                 ],
                                         minChainDepth: 1,
                                         chainDepthRange: 0,
                                         endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 badsignature: (invalidCert == "rootca"),
                 startTime: "2019-06-01 14:01:02", duration: 2, durationUnit: "years",
                 countries: null,
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [[subjectPermissions: [
                         [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                         [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                         [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                         [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                         [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                         [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                         [psid: 141, sspValue: "00", sspBitmask: "FF"],
                         [psid: 623, sspValue: "01FE", sspBitmask: "FF01"],
                 ],
                                         minChainDepth: 2,
                                         chainDepthRange: 0,
                                         endEntityType: [app: true, enroll: true]]
                 ]
                ]
        ])
    }

    static Certificate[] genExpiredChain(String expiredCert){
        return genCertChain([
                [type: "ec",
                 name: "Test EC",
                 startTime: (expiredCert == "endentity" ? "2001-08-01 14:01:02" : "2019-08-01 14:01:02"), duration: 24, durationUnit: "hours",
                 countries: [12,14],
                 appPermissions: [[psid: 623, bitmapSsp: "01C0"]]
                ],
                [type: "subca",
                 name: "Test EA",
                 startTime: (expiredCert == "subca" ? "2001-08-01 14:01:02" : "2019-07-01 14:01:02"), duration: 1, durationUnit: "years",
                 countries: [8,12,14,16],
                 appPermissions: [[psid: 623, bitmapSsp: "010E"]],
                 certIssuePermissions: [[subjectPermissions: [
                         [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                         [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                         [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                         [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                         [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                         [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                         [psid: 141, sspValue: "00", sspBitmask: "FF"],
                         [psid: 623, sspValue: "01C0", sspBitmask: "FF3F"],
                 ],
                                         minChainDepth: 1,
                                         chainDepthRange: 0,
                                         endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 startTime: (expiredCert == "rootca" ? "2001-08-01 14:01:02" : "2019-06-01 14:01:02"), duration: 2, durationUnit: "years",
                 countries: null,
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [[subjectPermissions: [
                         [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                         [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                         [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                         [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                         [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                         [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                         [psid: 141, sspValue: "00", sspBitmask: "FF"],
                         [psid: 623, sspValue: "01FE", sspBitmask: "FF01"],
                 ],
                                         minChainDepth: 2,
                                         chainDepthRange: 0,
                                         endEntityType: [app: true, enroll: true]]
                 ]
                ]
        ])
    }

    static Certificate[] genInvalidRegion(String invalidRegionCert){
        return genCertChain([
                [type: "ec",
                 name: "Test EC",
                 startTime:  "2019-08-01 14:01:02", duration: 24, durationUnit: "hours",
                 countries: (invalidRegionCert == "endentity" ? [13] : [12,14]),
                 appPermissions: [[psid: 623, bitmapSsp: "01C0"]]
                ],
                [type: "subca",
                 name: "Test EA",
                 startTime:  "2019-07-01 14:01:02", duration: 1, durationUnit: "years",
                 countries: (invalidRegionCert == "subca" ? [13] : [8,12,14,16]),
                 appPermissions: [[psid: 623, bitmapSsp: "010E"]],
                 certIssuePermissions: [[subjectPermissions: [
                         [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                         [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                         [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                         [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                         [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                         [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                         [psid: 141, sspValue: "00", sspBitmask: "FF"],
                         [psid: 623, sspValue: "01C0", sspBitmask: "FF3F"],
                 ],
                                         minChainDepth: 1,
                                         chainDepthRange: 0,
                                         endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 startTime: "2019-06-01 14:01:02", duration: 2, durationUnit: "years",
                 countries: (invalidRegionCert == "rootca" ? [13] : [8,12,14,16]),
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [[subjectPermissions: [
                         [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                         [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                         [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                         [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                         [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                         [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                         [psid: 141, sspValue: "00", sspBitmask: "FF"],
                         [psid: 623, sspValue: "01FE", sspBitmask: "FF01"],
                 ],
                                         minChainDepth: 2,
                                         chainDepthRange: 0,
                                         endEntityType: [app: true, enroll: true]]
                 ]
                ]
        ])
    }

    static Certificate[] genInvalidPermissions(String invalidPermissionCert){
        return genCertChain([
                [type: "ec",
                 name: "Test EC",
                 startTime:  "2019-08-01 14:01:02", duration: 24, durationUnit: "hours",
                 countries:  [12,14],
                 appPermissions: [[psid: 623, bitmapSsp: (invalidPermissionCert == "endentity" ? "01FF": "01C0")]]
                ],
                [type: "subca",
                 name: "Test EA",
                 startTime:  "2019-07-01 14:01:02", duration: 1, durationUnit: "years",
                 countries:  [8,12,14,16],
                 appPermissions: [[psid: 623, bitmapSsp: (invalidPermissionCert == "subca" ? "01FF":"010E")]],
                 certIssuePermissions: [[subjectPermissions: [
                         [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                         [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                         [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                         [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                         [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                         [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                         [psid: 141, sspValue: "00", sspBitmask: "FF"],
                         [psid: 623, sspValue: "01C0", sspBitmask: "FF3F"],
                 ],
                                         minChainDepth: 1,
                                         chainDepthRange: 0,
                                         endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 startTime: "2019-06-01 14:01:02", duration: 2, durationUnit: "years",
                 countries: null,
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [[subjectPermissions: [
                         [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                         [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                         [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                         [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                         [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                         [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                         [psid: 141, sspValue: "00", sspBitmask: "FF"],
                         [psid: 623, sspValue: "01FE", sspBitmask: "FF01"],
                 ],
                                         minChainDepth: 2,
                                         chainDepthRange: 0,
                                         endEntityType: [app: true, enroll: true]]
                 ]
                ]
        ])
    }

    static Certificate[] genCertChain(List specification){
        Certificate[] certChain = new Certificate[specification.size()]
        ETSIAuthorityCertGenerator authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager)
        ETSIEnrollmentCredentialGenerator enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(cryptoManager)
        ETSIAuthorizationTicketGenerator authorizationTicketGenerator = new ETSIAuthorizationTicketGenerator(cryptoManager)

        KeyPair issuerKeys

        for(int i=specification.size()-1;i>=0;i--){
            Map m = specification[i]

            def validityPeriod = genValidityPeriod(m)
            GeographicRegion region = genRegion(m)
            CertificateId name = new CertificateId(new Hostname((String) m.name))
            PsidSsp[] appPermissions = genAppPermissions(m.appPermissions)
            PsidGroupPermissions[] certIssuePermissions = genCertIssuePermissions(m.certIssuePermissions)

            KeyPair keys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)
            if(m.badsignature){
                issuerKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)
            }
            switch (m.type){
                case "rootca":
                    PrivateKey signingKey =  keys.getPrivate()
                    if(m.badsignature){
                        signingKey = issuerKeys.getPrivate()
                    }
                    certChain[i] = authorityCertGenerator.genRootCA(name, // caName
                            validityPeriod, //ValidityPeriod
                            region, //GeographicRegion
                            null, //Subject Assurance
                            appPermissions,
                            certIssuePermissions,
                            Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                            keys.getPublic(), // signPublicKey
                            signingKey, // signPrivateKey
                            SymmAlgorithm.aes128Ccm, // symmAlgorithm
                            BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                            keys.getPublic())
                    break
                case "subca":
                    certChain[i] = authorityCertGenerator.genSubCA(name, // CA Name
                            validityPeriod,
                            region,  //GeographicRegion
                            null, // subject assurance (optional)
                            appPermissions,
                            certIssuePermissions,
                            Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                            keys.getPublic(), // signPublicKey, i.e public key in certificate
                            certChain[i+1], // signerCertificate
                            issuerKeys.getPublic(), // signCertificatePublicKey, must be specified separately to support implicit certificates.
                            issuerKeys.getPrivate(),
                            SymmAlgorithm.aes128Ccm, // symmAlgorithm
                            BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                            keys.getPublic() // encryption public key
                    )
                    break
                case "ec":
                    certChain[i] = enrollmentCredentialCertGenerator.genEnrollCredential(
                            (String) m.name, // unique identifier name
                            validityPeriod,
                            region,
                            null,
                            appPermissions,
                            Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                            keys.getPublic(), // signPublicKey, i.e public key in certificate
                            certChain[i+1], // signerCertificate
                            issuerKeys.getPublic(), // signCertificatePublicKey,
                            issuerKeys.getPrivate(),
                            SymmAlgorithm.aes128Ccm, // symmAlgorithm
                            BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
                            keys.getPublic() // encryption public key
                    )
                    break
                case "at":
                    certChain[i] = authorizationTicketGenerator.genAuthorizationTicket(
                            validityPeriod,
                            region,
                            null,
                            appPermissions,
                            Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                            keys.getPublic(), // signPublicKey, i.e public key in certificate
                            certChain[i+1], // signerCertificate
                            issuerKeys.getPublic(), // signCertificatePublicKey,
                            issuerKeys.getPrivate(),
                            SymmAlgorithm.aes128Ccm, // symmAlgorithm
                            BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
                            keys.getPublic() // encryption public key
                    )
                    break
            }
            issuerKeys = keys
        }

        return certChain
    }


    static PsidSsp[] genAppPermissions(List appPermissions){
        List<PsidSsp> servicePermissions = []
        appPermissions.each{ Map m ->
            Psid psId = new Psid((long) m.psid)
            PsidSsp psidSsp
            if(m.opaque){
                psidSsp = new PsidSsp(psId,new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,
                        Hex.decode((String) m.opaque)))
            }else if(m.bitmapSsp){
                psidSsp = new PsidSsp(psId,new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.bitmapSsp,
                        new BitmapSsp(Hex.decode((String) m.bitmapSsp))))
            }else{
                psidSsp = new PsidSsp(psId,null)
            }
            servicePermissions << psidSsp
        }
        if(servicePermissions.size() == 0){
            return null
        }
        return servicePermissions as PsidSsp[]
    }

    static PsidGroupPermissions[] genCertIssuePermissions(List certIssuePermissions){
        List<PsidGroupPermissions> groupPermissions = []
        certIssuePermissions.each{ Map m ->
            int minChainDepth = (Integer) m.minChainDepth
            int chainDepthRange = (Integer)  m.chainDepthRange
            EndEntityType endEntityType = genEndEntityType((Map) m.endEntityType)
            SubjectPermissions subjectPermissions = genSubjectPermissions((List) m.subjectPermissions)
            groupPermissions << new PsidGroupPermissions(subjectPermissions,minChainDepth,chainDepthRange,endEntityType)
        }
        if(groupPermissions.size() == 0){
            return null
        }
        return groupPermissions as PsidGroupPermissions[]
    }

    static EndEntityType genEndEntityType(Map m){
        return new EndEntityType((Boolean) m.app,(Boolean) m.enroll)
    }

    static SubjectPermissions genSubjectPermissions(List subjectPermissions){
        if(subjectPermissions == null){
            return new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null)
        }
        List<PsidSspRange> psidSspRangeList = []
        subjectPermissions.each { Map m ->
            Psid psId = new Psid((long) m.psid)
            SspRange sspRange = null
            if(m.all){
                sspRange = new SspRange(SspRange.SspRangeChoices.all)
            }else if(m.opaque){
                List<String> opaqueDatas = m.opaque
                sspRange = new SspRange(SspRange.SspRangeChoices.opaque, new SequenceOfOctetString(opaqueDatas.collect { new COEROctetStream(Hex.decode(it))}))
            }else if(m.sspBitmask){
                byte[] bitmask = Hex.decode((String) m.sspBitmask)
                byte[] sspValue = Hex.decode((String) m.sspValue)
                sspRange = new SspRange(SspRange.SspRangeChoices.bitmapSspRange, new BitmapSspRange(sspValue,bitmask))
            }
            psidSspRangeList << new PsidSspRange(psId, sspRange)

        }
        return new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.explicit, new SequenceOfPsidSspRange(psidSspRangeList))
    }

    private static GeographicRegion genRegion(Map m){
        if(m.useCountryAndRegion){
            CountryAndRegions countryAndRegions = new CountryAndRegions(new CountryOnly(4), new SequenceOfUint8([new Uint8(12), new Uint8(41), new Uint8(12)]))
            IdentifiedRegion identifiedRegion = new IdentifiedRegion(IdentifiedRegion.IdentifiedRegionChoices.countryAndRegions, countryAndRegions)
            GeographicRegion region = new GeographicRegion(GeographicRegion.GeographicRegionChoices.identifiedRegion,new SequenceOfIdentifiedRegion(identifiedRegion))
            return region
        }
        if(m.useCountryAndSubregions){
            RegionAndSubregions regionAndSubregions = new RegionAndSubregions(4,new SequenceOfUint16([new Uint16(4), new Uint16(5), new Uint16(6)]))
            CountryAndSubregions countryAndSubregions = new CountryAndSubregions(new CountryOnly(5), new SequenceOfRegionAndSubregions([regionAndSubregions]))
            IdentifiedRegion identifiedRegion = new IdentifiedRegion(IdentifiedRegion.IdentifiedRegionChoices.countryAndSubregions, countryAndSubregions)
            GeographicRegion region = new GeographicRegion(GeographicRegion.GeographicRegionChoices.identifiedRegion,new SequenceOfIdentifiedRegion(identifiedRegion))
            return region
        }
        if(m.useCircularRegion){
            CircularRegion circularRegion = new CircularRegion(new TwoDLocation(new Latitude(40), new Longitude(33)), 4000)
            GeographicRegion region = new GeographicRegion(GeographicRegion.GeographicRegionChoices.circularRegion,circularRegion)
            return region
        }
        return m.countries == null ? null : GeographicRegion.generateRegionForCountrys((List) m.countries)
    }

    private static SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")

    private toDate(String dateString){
        return simpleDateFormat.parse(dateString)
    }

    private static ValidityPeriod genValidityPeriod(Map m){
        Date startDate = simpleDateFormat.parse((String) m.startTime)
        Duration duration = new Duration(Duration.DurationChoices.valueOf((String) m.durationUnit), (int) m.duration)
        return new ValidityPeriod(new Time32(startDate), duration)
    }
}
