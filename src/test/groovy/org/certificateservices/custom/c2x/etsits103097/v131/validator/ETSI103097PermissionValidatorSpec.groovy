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
package org.certificateservices.custom.c2x.etsits103097.v131.validator


import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType
import spock.lang.Specification

import static org.certificateservices.custom.c2x.etsits103097.v131.validator.SecuredCertificateRequestServicePermissions.*
import static org.certificateservices.custom.c2x.ieee1609dot2.validator.BasePermissionValidatorSpec.*

/**
 * Unit tests for ETSI108097PermissionValidator and some methods of BasePermissionValidator.
 */
class ETSI103097PermissionValidatorSpec extends Specification {

    ETSI103097PermissionValidator permissionValidator = new ETSI103097PermissionValidator()

    def setupSpec(){
        initCryptoManager()
    }

    def "Verify that checkPermissions doesn't throw any exceptions for a valid chain"(){
        setup:
        def chain = genValidChain()
        when:
        //printChain(chain)
        permissionValidator.checkPermissions(new EndEntityType(false,true), chain, true)
        permissionValidator.checkCertServicePermissionInAppPermissions(VERSION_1, (byte) (SIGN_ENROL_REQ | SIGN_AUTH_REQ), chain)
        then:
        true
        when:
        // Verify it does not have permission to SIGN ENROL_RESP
        permissionValidator.checkCertServicePermissionInAppPermissions(VERSION_1, (byte) (SIGN_ENROL_RESP | SIGN_AUTH_REQ), chain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Couldn't find permission for SecuredCertificateRequestService (623): 0144 in certificate."
    }

    def "Verify that checkCertServicePermissionInIssuePermissions verifies permissions properly"(){
        setup:
        def fullChain = genValidChain()
        def issuerChain = [fullChain[1],fullChain[2]] as Certificate[]
        when:
        permissionValidator.checkCertServicePermissionInIssuePermissions(VERSION_1, (byte) (SIGN_ENROL_REQ), new EndEntityType(false,true),1, issuerChain)
        permissionValidator.checkCertServicePermissionInIssuePermissions(VERSION_1, (byte) ((SIGN_ENROL_REQ) | (SIGN_AUTH_REQ)), new EndEntityType(false,true),1, issuerChain)
        then:
        true

        when: // Verify that invalid permissions throws InvalidCertificateException
        permissionValidator.checkCertServicePermissionInIssuePermissions(VERSION_1, (byte) (SIGN_ENROL_RESP), new EndEntityType(false,true),1, issuerChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Couldn't find issue permission for SecuredCertificateRequestService (623): 0104 in certificate."

    }

    def "Verify that checkPermissions throw InvalidCertificateChain for invalid endEntityType"(){
        when:
        permissionValidator.checkPermissions(new EndEntityType(true,false),  genValidChain(), true)
        then:
        thrown InvalidCertificateException
        when:
        permissionValidator.checkPermissions(new EndEntityType(true,true),  genValidChain(), true)
        then:
        thrown InvalidCertificateException
    }


    def "Verify that rootCA only is always accepted"(){
        setup:
        def rootCAOnlyChain = genCertChain([
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
        when:
        permissionValidator.checkPermissions(new EndEntityType(true,false), rootCAOnlyChain, true)
        then:
        true
        when: // Also with entireChain false
        permissionValidator.checkPermissions(new EndEntityType(true,false), rootCAOnlyChain, false)
        then:
        true
    }

    def "Verify that it is possible to issue an EA with AuthorizationValidation response only in appPermissions and the chain is still valid"(){
        setup:
        def chain = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 623, bitmapSsp: "0108"]]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
                            [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                            [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                            [psid: 137, sspValue: "01F8", sspBitmask: "FF07"],
                            [psid: 138, sspValue: "01E0", sspBitmask: "FF1F"],
                            [psid: 139, sspValue: "01940000FFF8", sspBitmask: "FF0000000007"],
                            [psid: 140, sspValue: "01FFFFFE", sspBitmask: "FF000001"],
                            [psid: 141, sspValue: "00", sspBitmask: "FF"],
                            [psid: 623, sspValue: "01FE", sspBitmask: "FF01"],
                 ],
                                         minChainDepth: 1,
                                         chainDepthRange: 1,
                                         endEntityType: [app: true, enroll: true]]
                 ]
                ]
        ])
        when:
        permissionValidator.checkPermissions(new EndEntityType(false,true), chain, true)
        // Check that
        permissionValidator.checkCertServicePermissionInAppPermissions(VERSION_1, SIGN_AUTH_VALIDATION_RESP, chain)
        then:
        true
        when:
        def chainWith2GroupPermissions = genCertChain([
                [type: "subca",
                 name: "Test EA Authorization Validation only",
                 appPermissions: [[psid: 623, bitmapSsp: "0108"]]
                ],
                [type: "rootca",
                 name: "Test Rootca",
                 appPermissions: [[psid: 624, bitmapSsp: "0138"],[psid: 622, bitmapSsp: "01"]],
                 certIssuePermissions: [
                         [subjectPermissions: [
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
                          endEntityType: [app: true, enroll: true]],
                         [subjectPermissions: [
                                 [psid: 623, sspValue: "0108", sspBitmask: "FFFF"],
                         ],
                          minChainDepth: 1,
                          chainDepthRange: 0,
                          endEntityType: [app: false, enroll: true]]
                 ]
                ]
        ])
        permissionValidator.checkPermissions(new EndEntityType(false,true), chainWith2GroupPermissions, true)
        permissionValidator.checkCertServicePermissionInAppPermissions(VERSION_1, SIGN_AUTH_VALIDATION_RESP, chain)
        then:
        true
        when: // Verify that it is not possible to sign certificate with Authorization Validation Only Certificate
        permissionValidator.checkCertServicePermissionInAppPermissions(VERSION_1,SIGN_ENROL_RESP, chain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Couldn't find permission for SecuredCertificateRequestService (623): 0104 in certificate."
    }

    def "Verify that parameter entireChain is false is only permissions of the end entity certificate against its issuer checked, not the entire chain"(){
        setup:
        def chainWithFaultySubCa = genCertChain([
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
                         [psid: 142, sspValue: "00", sspBitmask: "FF"],
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

        when:
        permissionValidator.checkPermissions(new EndEntityType(false,true), chainWithFaultySubCa, false)
        then:
        true
        when:
        permissionValidator.checkPermissions(new EndEntityType(false,true), chainWithFaultySubCa, true)
        then:
        def e = thrown InvalidCertificateException
        e.message == "No matching issuer permissions for PSID 142 exists in issuer certificate."


    }




}
