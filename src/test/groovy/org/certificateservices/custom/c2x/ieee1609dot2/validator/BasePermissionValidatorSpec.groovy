/************************************************************************
 *                                                                       *
 *  Certificate Service - Car2Car Core                                  *
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
import org.certificateservices.custom.c2x.common.crypto.CryptoManager
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorizationTicketGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.validator.ETSI103097PermissionValidator
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BitmapSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BitmapSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfOctetString
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsidSspRange
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions
import spock.lang.Specification

import java.security.KeyPair

/**
 * Unit tests for BasePermissionValidator using ETSI103097PermissionValidator implementation to
 * run the checks. Some aspects are tested in ETSI103097PermissionValidatorSpec.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class BasePermissionValidatorSpec extends Specification {

    ETSI103097PermissionValidator permissionValidator = new ETSI103097PermissionValidator()

    static Ieee1609Dot2CryptoManager cryptoManager

    def setupSpec(){
        initCryptoManager()
    }

    static void initCryptoManager(){
        cryptoManager = new DefaultCryptoManager()
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
    }

    def "Verify that certificate that has subject permissions all accpets all permissions"(){
        setup:
        def chainWithAllPermissions = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 622, bitmapSsp: "0108"],[psid: 623, bitmapSsp: "0108"]]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [[
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                  ]
                ]

        ])
        when:
        //printChain(chainWithAllPermissions)
        permissionValidator.checkPermissions(new EndEntityType(false,true), chainWithAllPermissions)
        then:
        true
    }

    def "Verify that certificate that has subject permissions all and specific permissions for given PSID, then is given PSID evaluated"(){
        setup:
        def chainWithAllPermissions = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 622, bitmapSsp: "0108"],[psid: 623, bitmapSsp: "0108"]]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [[
                                                minChainDepth: 1,
                                                chainDepthRange: 0,
                                                endEntityType: [app: false, enroll: true]],
                                        [
                                                subjectPermissions: [
                                                        [psid: 623, sspValue: "0109", sspBitmask: "FFFF"],
                                                ],
                                                minChainDepth: 1,
                                                chainDepthRange: 0,
                                                endEntityType: [app: false, enroll: true]]

                 ]
                ]

        ])
        when:
        //printChain(chainWithAllPermissions)
        permissionValidator.checkPermissions(new EndEntityType(false,true), chainWithAllPermissions)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid PsidGroupPermissions for PSID 623, No matching PsidGroupPermissions found in issuer certificate."
    }

    def "Verify that appPermissions with two of the same PSID throwsInvalidCertificateException "(){
        when:
        def chainWithInvalidBitmaskLength = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 622, bitmapSsp: "0108"],[psid: 623, bitmapSsp: "0108"],[psid: 623, bitmapSsp: "0108"]]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "0108", sspBitmask: "FFFF"],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), chainWithInvalidBitmaskLength)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid sequenceOfPsidSsp found in certificate permissions, duplicate PSID 623 found."
    }

    def "Verify that length of bitmapSSP is checked against Bitmask in BitmapSSPRange"(){
        when:
        def chainWithInvalidBitmaskLength = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 623, bitmapSsp: "0108"]]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "010801", sspBitmask: "FFFF01"],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), chainWithInvalidBitmaskLength)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid PsidSspRange for PSID 623, bitmap in certificate have different length."
    }

    def "Verify that length of bitmapSSP is checked against opaque in SSPRange"(){
        when:
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 623, bitmapSsp: "0108"]]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["0108"]],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), chain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid PsidSspRange for PSID 623, issuer SSPRange is of type opaque, not expected bitmapSspRange."
    }

    def "Verify that sspData with no valid permissions id issuer certificate generates InvalidCertificateException"(){
        when:
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 623, bitmapSsp: "0108"]]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "0109", sspBitmask: "FFFF"],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), chain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid PsidGroupPermissions for PSID 623, No matching PsidGroupPermissions found in issuer certificate."
    }

    def "Verify that any sspData with valid for PSIDSSPRange is of type all"(){
        when:
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 623, bitmapSsp: "0108"]]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, all: true],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), chain)
        then:
        true
    }


    def "Verify that bitmask length of bitmapSSPRange is checked against Bitmask in BitmapSSPRange"(){
        when:
        def chainWithInvalidBitmaskLength = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "010801", sspBitmask: "FFFF01"],
                         ],
                          minChainDepth: 0,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "010801", sspBitmask: "FFFFFF01"],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), chainWithInvalidBitmaskLength)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid PsidGroupPermissions for PSID 623, bitmaps in certificate have different length."
    }

    def "Verify that checkPermissions if bitmapSSPRange is checked against an opaque bitmapSSPRange in issuer is InvalidCertificateException thrown."(){
        when:
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "010801", sspBitmask: "FFFF01"],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["010801"]],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), 1, chain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid PsidGroupPermissions for PSID 623, issuer SSPRange is of type opaque, not expected bitmapSspRange."
    }

    def "Verify that checkPermissions if bitmapSSPRange have a bitmask that is not compliant with issuers bitmask"(){
        when:
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "010801", sspBitmask: "FFFF02"],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "010801", sspBitmask: "FFFF01"],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), 1, chain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid PsidGroupPermissions for PSID 623, No matching PsidGroupPermissions found in issuer certificate."
    }

    def "Verify that checkPermissions if bitmapSSPRange have a different sspValue than was allowed in issuer's bitmapSSPRange throws InvalidCertificateException."(){
        when:
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "0109", sspBitmask: "FFFF"],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "0108", sspBitmask: "FFFF"],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), 1, chain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid PsidGroupPermissions for PSID 623, No matching PsidGroupPermissions found in issuer certificate."
    }

    def "Verify that checkPermissions allows any bitmapSSPRange if issuer certificate is of type all"(){
        when:
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "0109", sspBitmask: "FFFF"],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, all: true],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), chain)
        then:
        true
    }

    def "Verify that checkPermissions allows doesn't allow bitmapSSPRange spp type all if issuer does not also have ssp type all"(){
        when:
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, all: true],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "0109", sspBitmask: "FFFF"],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), 1, chain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "No issuer permission with SspRange of type all found for PSID 623."

        when: // Verify it both cert and issuer has all is accepted
        chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, all: true],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, all: true],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), chain)
        then:
        true
    }

    def "Verify that PSIDSSP verifies opaque data correctly"(){
        when: // Verify valid data
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 623, opaque: "010203"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["010203","010204"]],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["010203","010204"]],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        then:
        permissionValidator.checkPermissions(new EndEntityType(false,true), 1, chain)
        when: // Verify when appPermission does not match list in issuer
        chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 623, opaque: "010205"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["010203","010204"]],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["010203","010204"]],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), 1, chain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid PsidSsp Permissions for PSID 623, no matching octet stream found in issuer."
        when: // Verify when issuerPermission does not match list in issuer
        chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 623, opaque: "010204"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["010203","010205"]],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["010203","010204"]],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), 1, chain)
        then:
        e = thrown InvalidCertificateException
        e.message == "Invalid PsidSspRange for PSID: 623 could not find matching permissions in issuer certificate."

        when: // Verify when issuerPermission has more octets streams than in issuer
        chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 623, opaque: "010204"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["010203","010204","010205"]],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["010203","010204"]],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), 1, chain)
        then:
        e = thrown InvalidCertificateException
        e.message == "Invalid PsidSspRange for PSID: 623 could not find matching permissions in issuer certificate."
    }

    def "Verify that checkPermissions allows any opaque if issuer certificate is of type all"(){
        when:
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["FFFF"]],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, all: true],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), chain)
        then:
        true
    }

    def "Verify that checkPermissions allows doesn't allow opaque spp type all if issuer does not also have ssp type all"(){
        when:
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, all: true],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                                 [psid: 623, opaque: ["010203"]],
                         ],
                          minChainDepth: 2,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), 1, chain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "No issuer permission with SspRange of type all found for PSID 623."

    }


    def "Verify that filterByEndEntityTypeAndChainLength only returns PsidGroupPermissions with specified end entity types"(){
        when:
        def result = permissionValidator.filterByEndEntityTypeAndChainLength(new EndEntityType(false, true),
                1,genCertIssuePermissions([
                [
                        subjectPermissions: [[psid: 623, opaque: ["010203"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: false, enroll: true]
                ],
                [
                        subjectPermissions: [[psid: 624, opaque: ["010204"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: true, enroll: false]
                ],
                [
                        subjectPermissions: [[psid: 625, opaque: ["010204"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: false, enroll: true]
                ]
        ]))

        then:
        permissionValidator.filterPsidSspRangeByPSID(623,result).size() == 1
        permissionValidator.filterPsidSspRangeByPSID(625,result).size() == 1
        permissionValidator.filterPsidSspRangeByPSID(624,result).size() == 0

        when:
        result = permissionValidator.filterByEndEntityTypeAndChainLength(new EndEntityType(true, false),
                1,genCertIssuePermissions([
                [
                        subjectPermissions: [[psid: 623, opaque: ["010203"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: false, enroll: true]
                ],
                [
                        subjectPermissions: [[psid: 624, opaque: ["010204"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: true, enroll: false]
                ],
                [
                        subjectPermissions: [[psid: 625, opaque: ["010204"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: false, enroll: true]
                ]
        ]))

        then:
        permissionValidator.filterPsidSspRangeByPSID(623,result).size() == 0
        permissionValidator.filterPsidSspRangeByPSID(625,result).size() == 0
        permissionValidator.filterPsidSspRangeByPSID(624,result).size() == 1

        when:
        result = permissionValidator.filterByEndEntityTypeAndChainLength(new EndEntityType(true, true),
                1,genCertIssuePermissions([
                [
                        subjectPermissions: [[psid: 623, opaque: ["010203"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: false, enroll: true]
                ],
                [
                        subjectPermissions: [[psid: 624, opaque: ["010204"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: true, enroll: false]
                ],
                [
                        subjectPermissions: [[psid: 625, opaque: ["010204"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: false, enroll: true]
                ]
        ]))

        then:
        result.size() == 0

        when:
        result = permissionValidator.filterByEndEntityTypeAndChainLength(new EndEntityType(true, true),
                1,genCertIssuePermissions([
                [
                        subjectPermissions: [[psid: 623, opaque: ["010203"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: false, enroll: true]
                ],
                [
                        subjectPermissions: [[psid: 624, opaque: ["010204"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: true, enroll: true]
                ],
                [
                        subjectPermissions: [[psid: 625, opaque: ["010204"]]],
                        minChainDepth: 1,
                        chainDepthRange: 0,
                        endEntityType: [app: false, enroll: true]
                ]
        ]))

        then:
        result.size() == 1
        permissionValidator.filterPsidSspRangeByPSID(624,result).size() == 1
    }

    def "Verify that filterByEndEntityTypeAndChainLength only returns PsidGroupPermissions with specified chain length"(){
        setup:
        def certIssuerPerms = genCertIssuePermissions([
                [
                        subjectPermissions: [[psid: 623, opaque: ["010203"]]],
                        minChainDepth: 2,
                        chainDepthRange: 0,
                        endEntityType: [app: false, enroll: true]
                ],
                [
                        subjectPermissions: [[psid: 624, opaque: ["010204"]]],
                        minChainDepth: 0,
                        chainDepthRange: 1,
                        endEntityType: [app: false, enroll: true]
                ],
                [
                        subjectPermissions: [[psid: 625, opaque: ["010204"]]],
                        minChainDepth: 2,
                        chainDepthRange: 2,
                        endEntityType: [app: false, enroll: true]
                ],
                [
                        subjectPermissions: [[psid: 626, opaque: ["010204"]]],
                        minChainDepth: 4,
                        chainDepthRange: 3,
                        endEntityType: [app: false, enroll: true]
                ]
        ])
        when:
        def result = permissionValidator.filterByEndEntityTypeAndChainLength(new EndEntityType(false, true),
                1,certIssuerPerms)
        then:
        result.size() == 1
        permissionValidator.filterPsidSspRangeByPSID(624,result).size() == 1
        when:
        result = permissionValidator.filterByEndEntityTypeAndChainLength(new EndEntityType(false, true),
                2,certIssuerPerms)
        then:
        result.size() == 2
        permissionValidator.filterPsidSspRangeByPSID(623,result).size() == 1
        permissionValidator.filterPsidSspRangeByPSID(625,result).size() == 1
        when:
        result = permissionValidator.filterByEndEntityTypeAndChainLength(new EndEntityType(false, true),
                7,certIssuerPerms)
        then:
        result.size() == 1
        permissionValidator.filterPsidSspRangeByPSID(626,result).size() == 1

    }


    static Certificate[] genValidChain(){
        return genCertChain([
                [type: "ec",
                 name: "Test EC",
                 appPermissions: [[psid: 623, bitmapSsp: "01C0"]]
                ],
                [type: "subca",
                 name: "Test EA",
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
        KeyPair keys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)


        for(int i=specification.size()-1;i>=0;i--){
            Map m = specification[i]
            def validityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 45);

            CertificateId name = new CertificateId(new Hostname((String) m.name))
            PsidSsp[] appPermissions = genAppPermissions(m.appPermissions)
            PsidGroupPermissions[] certIssuePermissions = genCertIssuePermissions(m.certIssuePermissions)


            switch (m.type){
                case "rootca":
                    certChain[i] = authorityCertGenerator.genRootCA(name, // caName
                            validityPeriod, //ValidityPeriod
                            null, //GeographicRegion
                            null, //Subject Assurance
                            appPermissions,
                            certIssuePermissions,
                            Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                            keys.getPublic(), // signPublicKey
                            keys.getPrivate(), // signPrivateKey
                            SymmAlgorithm.aes128Ccm, // symmAlgorithm
                            BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                            keys.getPublic())
                    break
                case "subca":
                    certChain[i] = authorityCertGenerator.genSubCA(name, // CA Name
                            validityPeriod,
                            null,  //GeographicRegion
                            null, // subject assurance (optional)
                            appPermissions,
                            certIssuePermissions,
                            Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                            keys.getPublic(), // signPublicKey, i.e public key in certificate
                            certChain[i+1], // signerCertificate
                            keys.getPublic(), // signCertificatePublicKey, must be specified separately to support implicit certificates.
                            keys.getPrivate(),
                            SymmAlgorithm.aes128Ccm, // symmAlgorithm
                            BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                            keys.getPublic() // encryption public key
                    )
                    break
                case "ec":
                    certChain[i] = enrollmentCredentialCertGenerator.genEnrollCredential(
                            (String) m.name, // unique identifier name
                            validityPeriod,
                            null,
                            null,
                            appPermissions,
                            Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                            keys.getPublic(), // signPublicKey, i.e public key in certificate
                            certChain[i+1], // signerCertificate
                            keys.getPublic(), // signCertificatePublicKey,
                            keys.getPrivate(),
                            SymmAlgorithm.aes128Ccm, // symmAlgorithm
                            BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
                            keys.getPublic() // encryption public key
                    )
                    break
                case "at":
                    certChain[i] = authorizationTicketGenerator.genAuthorizationTicket(
                            validityPeriod,
                            null,
                            null,
                            appPermissions,
                            Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                            keys.getPublic(), // signPublicKey, i.e public key in certificate
                            certChain[i+1], // signerCertificate
                            keys.getPublic(), // signCertificatePublicKey,
                            keys.getPrivate(),
                            SymmAlgorithm.aes128Ccm, // symmAlgorithm
                            BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
                            keys.getPublic() // encryption public key
                    )
                    break
            }
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

    static void printChain(Certificate[] chain){
        chain.each{
            println "---------------------------------------------"
            println it
        }
    }
}
