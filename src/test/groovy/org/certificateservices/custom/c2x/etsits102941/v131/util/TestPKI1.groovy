package org.certificateservices.custom.c2x.etsits102941.v131.util

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CRL
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CTL
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.validator.BasePermissionValidatorSpec

import java.security.KeyPair
import java.text.SimpleDateFormat;

import static org.certificateservices.custom.c2x.etsits102941.v131.util.Etsi102941CTLHelperSpec.*
import static org.certificateservices.custom.c2x.etsits102941.v131.util.Etsi102941CRLHelperSpec.*

/**
 * Class that generates a Test PKI with Root CAs, EA and AAs with CTL and CRL used for verifying CTL and CRL.
 *
 * @author Philip Vendil
 */
class TestPKI1 {

    static SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")

    KeyPair tlmSigningKeys
    EtsiTs103097Certificate tlm
    EtsiTs102941CTL fullTlmCtl
    EtsiTs102941CTL deltaTlmCtl

    KeyPair rootCA1SigningKeys
    EtsiTs103097Certificate rootca1
    EtsiTs102941CTL fullRootCA1Ctl
    EtsiTs102941CTL deltaRootCA1Ctl
    EtsiTs102941CRL rootCA1Crl
    EtsiTs102941CRL emptyRootCA1Crl
    KeyPair rootCA1EA1SigningKeys
    EtsiTs103097Certificate rca1_ea1
    KeyPair rootCA1EA1EC1SigningKeys
    EtsiTs103097Certificate rca1_ea1_ec1
    KeyPair rootCA1EA2SigningKeys
    EtsiTs103097Certificate rca1_ea2
    KeyPair rootCA1EA2EC1SigningKeys
    EtsiTs103097Certificate rca1_ea2_ec1
    EtsiTs103097Certificate rca1_aa1
    EtsiTs103097Certificate rca1_aa2


    KeyPair rootCA2SigningKeys
    EtsiTs103097Certificate rootca2
    EtsiTs102941CTL fullRootCA2Ctl
    EtsiTs102941CTL deltaRootCA2Ctl
    EtsiTs103097Certificate rca2_ea1
    EtsiTs103097Certificate rca2_aa1

    KeyPair rootCA3SigningKeys
    EtsiTs103097Certificate rootca3
    EtsiTs102941CTL fullRootCA3Ctl
    EtsiTs102941CRL rootCA3Crl
    EtsiTs103097Certificate rca3_ea1



        TestPKI1(){
            def cryptoManager = BasePermissionValidatorSpec.cryptoManager
            tlmSigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)
            tlm = BasePermissionValidatorSpec.genCert(
                    [type: "tlm",
                    name: "Some TLM",
                     startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "years",
                    appPermissions: [[psid: 624, bitmapSsp: "0140"]]
                    ],tlmSigningKeys, null)

            rootCA1SigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)
            rootca1 = BasePermissionValidatorSpec.genCert(
                    [type: "rootca",
                    name: "Test RootCA1",
                     startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "years",
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
                    , rootCA1SigningKeys, null)
            rootCA1EA1SigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)
            rca1_ea1 = BasePermissionValidatorSpec.genCert(
                    [type: "subca",
                    name: "Test RootCA1 EA1",
                     startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "years",
                     pubKey: rootCA1EA1SigningKeys.public,
                    appPermissions: [[psid: 623, bitmapSsp: "010E"]],
            certIssuePermissions: [[subjectPermissions: [
                             [psid: 623, sspValue: "01C0", sspBitmask: "FF3F"],
                     ],
            minChainDepth: 1,
                    chainDepthRange: 0,
                    endEntityType: [app: false, enroll: true]]
                     ]
                    ]
                    , rootCA1SigningKeys, rootca1)
            rootCA1EA1EC1SigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)
            rca1_ea1_ec1 = BasePermissionValidatorSpec.genCert(
                    [type: "ec",
                     name: "Test EA1 EC1",
                     startTime: "2019-08-01 14:01:02", duration: 3, durationUnit: "years",
                     appPermissions: [[psid: 623, bitmapSsp: "01C0"]],
                     pubKey: rootCA1EA1EC1SigningKeys.public]
                    , rootCA1EA1SigningKeys, rca1_ea1)
            rootCA1EA2SigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)
            rca1_ea2 = BasePermissionValidatorSpec.genCert(
                    [type: "subca",
                     name: "Test RootCA1 EA2",
                            pubKey: rootCA1EA2SigningKeys.public,
                     appPermissions: [[psid: 623, bitmapSsp: "010E"]],
                     certIssuePermissions: [[subjectPermissions: [
                             [psid: 623, sspValue: "01C0", sspBitmask: "FF3F"],
                     ],
                                             minChainDepth: 1,
                                             chainDepthRange: 0,
                                             endEntityType: [app: false, enroll: true]]
                     ]
                    ]
                    , rootCA1SigningKeys, rootca1)
            rootCA1EA2EC1SigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)
            rca1_ea2_ec1 = BasePermissionValidatorSpec.genCert(
                    [type: "ec",
                     name: "Test EA2 EC1",
                     appPermissions: [[psid: 623, bitmapSsp: "01C0"]],
                     pubKey: rootCA1EA2EC1SigningKeys.public]
                    , rootCA1EA2SigningKeys, rca1_ea2)
            rca1_aa1 = BasePermissionValidatorSpec.genCert(
                    [type: "subca",
                    name: "Test RootCA1 AA1",
                    appPermissions: [[psid: 623, bitmapSsp: "0132"]],
            certIssuePermissions: [[subjectPermissions: [
                             [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                             [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                     ],
            minChainDepth: 1,
                    chainDepthRange: 0,
                    endEntityType: [app: true, enroll: false]]
                     ]
                    ]
                    , rootCA1SigningKeys, rootca1)

            rca1_aa2 = BasePermissionValidatorSpec.genCert(
                    [type: "subca",
                    name: "Test RootCA1 AA2",
                    appPermissions: [[psid: 623, bitmapSsp: "0132"]],
            certIssuePermissions: [[subjectPermissions: [
                             [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                             [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                     ],
            minChainDepth: 1,
                    chainDepthRange: 0,
                    endEntityType: [app: true, enroll: false]]
                     ]
                    ]
                    , rootCA1SigningKeys, rootca1)


            rootCA2SigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)
            rootca2 = BasePermissionValidatorSpec.genCert(
                    [type: "rootca",
                    name: "Test RootCA2",
                     startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "years",
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
                    , rootCA2SigningKeys, null)

            rca2_ea1 = BasePermissionValidatorSpec.genCert(
                    [type: "subca",
                    name: "Test RootCA2 EA1",
                    appPermissions: [[psid: 623, bitmapSsp: "010E"]],
            certIssuePermissions: [[subjectPermissions: [
                             [psid: 623, sspValue: "01C0", sspBitmask: "FF3F"],
                     ],
            minChainDepth: 1,
                    chainDepthRange: 0,
                    endEntityType: [app: false, enroll: true]]
                     ]
                    ]
                    , rootCA2SigningKeys, rootca2)

            rca2_aa1 = BasePermissionValidatorSpec.genCert(
                    [type: "subca",
                    name: "Test RootCA2 AA1",
                    appPermissions: [[psid: 623, bitmapSsp: "0132"]],
            certIssuePermissions: [[subjectPermissions: [
                             [psid: 36, sspValue: "01FFFF", sspBitmask: "FF0000"],
                             [psid: 37, sspValue: "01FFFFFF", sspBitmask: "FF000000"],
                     ],
            minChainDepth: 1,
                    chainDepthRange: 0,
                    endEntityType: [app: true, enroll: false]]
                     ]
                    ]
                    , rootCA2SigningKeys, rootca2)

            rootCA3SigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)
            rootca3 = BasePermissionValidatorSpec.genCert(
                    [type: "rootca",
                    name: "Test RootCA3",
                     startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "years",
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
                    , rootCA3SigningKeys, null)

            rca3_ea1 = BasePermissionValidatorSpec.genCert(
                    [type: "subca",
                    name: "Test RootCA3 EA1",
                    appPermissions: [[psid: 623, bitmapSsp: "010E"]],
            certIssuePermissions: [[subjectPermissions: [
                             [psid: 623, sspValue: "01C0", sspBitmask: "FF3F"],
                     ],
            minChainDepth: 1,
                    chainDepthRange: 0,
                    endEntityType: [app: false, enroll: true]]
                     ]
                    ]
                    , rootCA3SigningKeys, rootca3)

            fullTlmCtl = genCTL([ type: "tlmctl",
                    nextUpdate: "2020-02-10 10:10:10",
                    sequence: 1,
                    commands:[[
            command: "add",
                    type: "rca",
                    selfsignedcert: rootca1

                                  ],[
            command: "add",
                    type: "rca",
                    selfsignedcert: rootca2
                                  ]],
            signerChain: [tlm],
            signerKey: tlmSigningKeys
            ])

            deltaTlmCtl = genCTL([ type: "tlmctl",
                    nextUpdate: "2020-02-11 10:11:10",
                    delta: true,
                    sequence: 1,
                    commands:[[
            command: "add",
                    type: "rca",
                    selfsignedcert: rootca3

                                            ],[
            command: "del",
                    type: "rca",
                    certId: rootca2.asHashedId8(cryptoManager)
                                            ]],
            signerChain: [tlm],
            signerKey: tlmSigningKeys
            ])

            fullRootCA1Ctl = genCTL([ type: "rcactl",
                    nextUpdate: "2020-02-10 10:10:10",
                    sequence: 1,
                    commands:[[
            command: "add",
                    type: "ea",
                    eacert: rca1_ea1,
                    aaaccesspoint: "http://someaaaccesspoint",
                    itsaccesspoint: "http://someitsaccesspoint"

                                            ],[
            command: "add",
                    type: "ea",
                    eacert: rca1_ea2,
                    aaaccesspoint: "http://someaaaccesspoint",
                    itsaccesspoint: "http://someitsaccesspoint"

                                            ],[
            command: "add",
                    type: "aa",
                    aacert: rca1_aa1,
                    accesspoint: "http://someaaaccesspoint"
                                            ],[
            command: "add",
                    type: "dc",
                    url: "http://somedc",
                    certIds: [rootca1.asHashedId8(cryptoManager),rootca2.asHashedId8(cryptoManager)]

                                  ]],
            signerChain: [rootca1],
            signerKey: rootCA1SigningKeys
            ])


            deltaRootCA1Ctl = genCTL([ type: "rcactl",
                    nextUpdate: "2020-02-08 10:11:10",
                    delta: true,
                    sequence: 1,
                    commands:[[
            command: "add",
                    type: "aa",
                    aacert: rca1_aa2,
                    accesspoint: "http://someaaaccesspoint"

                                                 ],[
            command: "del",
                    type: "ea",
                    certId: rca1_ea2.asHashedId8(cryptoManager)
                                                 ],[
            command: "del",
                    type: "dc",
                    url: "http://somedc"
                                                 ],[
            command: "add",
                    type: "dc",
                    url: "http://somedc2",
                    certIds: [rootca1.asHashedId8(cryptoManager),rootca2.asHashedId8(cryptoManager)]
                                                 ]],
            signerChain: [rootca1],
            signerKey: rootCA1SigningKeys
            ])

            rootCA1Crl = genCRL([thisUpdate : "2020-02-07 10:12:10",
                                 nextUpdate : "2020-03-07 10:11:10",
                                 entries    : [rca1_ea1, rca1_aa1],
                                 signerChain: [rootca1],
                                 signerKey  : rootCA1SigningKeys
            ]

            )
            emptyRootCA1Crl= genCRL([thisUpdate : "2020-02-07 10:12:10",
                                     nextUpdate : "2020-03-07 10:11:10",
                                     entries    : [],
                                     signerChain: [rootca1],
                                     signerKey  : rootCA1SigningKeys
            ]

            )

            fullRootCA2Ctl = genCTL([ type: "rcactl",
                    nextUpdate: "2020-02-07 10:10:10",
                    sequence: 1,
                    commands:[[
            command: "add",
                    type: "ea",
                    eacert: rca2_ea1,
                    aaaccesspoint: "http://someaaaccesspoint",
                    itsaccesspoint: "http://someitsaccesspoint"

                                                ]],
            signerChain: [rootca2],
            signerKey: rootCA2SigningKeys
            ])


            deltaRootCA2Ctl = genCTL([ type: "rcactl",
                    nextUpdate: "2020-02-07 10:11:10",
                    delta: true,
                    sequence: 1,
                    commands:[[
            command: "add",
                    type: "aa",
                    aacert: rca2_aa1,
                    accesspoint: "http://someaaaccesspoint"

                                                 ]],
            signerChain: [rootca1],
            signerKey: rootCA2SigningKeys
            ])

            rootCA3Crl = genCRL([thisUpdate : "2020-02-07 10:12:10",
                                 nextUpdate : "2020-03-07 10:11:10",
                                 entries    : [rca3_ea1],
                                 signerChain: [rootca3],
                                 signerKey  : rootCA3SigningKeys
            ]

            )

            fullRootCA3Ctl = genCTL([ type: "rcactl",
                                      nextUpdate: "2020-02-07 10:10:10",
                                      sequence: 1,
                                      commands:[[
                                                        command: "add",
                                                        type: "ea",
                                                        eacert: rca3_ea1,
                                                        aaaccesspoint: "http://someaaaccesspoint",
                                                        itsaccesspoint: "http://someitsaccesspoint"

                                                ]],
                                      signerChain: [rootca3],
                                      signerKey: rootCA3SigningKeys
            ])

        }

}
