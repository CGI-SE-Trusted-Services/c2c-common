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
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import java.security.KeyPair
import java.text.SimpleDateFormat

import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices.*

/**
 * Unit tests for Ieee1609Dot2TimeValidator
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class Ieee1609Dot2TimeValidatorSpec extends Specification {

    Ieee1609Dot2TimeValidator validator = new Ieee1609Dot2TimeValidator()
    @Shared Ieee1609Dot2CryptoManager cryptoManager

    def setupSpec(){
        cryptoManager = new DefaultCryptoManager()
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
    }

    def "Verify that a valid certificate chain doesn't throw InvalidCertificateException"(){
        setup:
        def certChain = genCertChain([[type: "endentity", name: "some endEntity", startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "hours"],
                                      [type: "subca", name: "some subca", startTime: "2019-07-01 14:01:02", duration: 1, durationUnit: "years"],
                                      [type: "rootca", name: "some rootca", startTime: "2019-06-01 14:01:02", duration: 2, durationUnit: "years"]])
        when:
        validator.validateTime(toDate("2019-08-01 15:01:02"), certChain)
        then:
        true
    }

    def "Verify that InvalidCertificateException is thrown if end entity certificate have expired"(){
        setup:
        def certChain = genCertChain([[type: "endentity", name: "some endEntity", startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "hours"],
                                      [type: "subca", name: "some subca", startTime: "2019-07-01 14:01:02", duration: 1, durationUnit: "years"],
                                      [type: "rootca", name: "some rootca", startTime: "2019-06-01 14:01:02", duration: 2, durationUnit: "years"]])
        when:
        validator.validateTime(toDate("2019-08-02 14:01:03"), certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Expired certificate exists in chain."
    }

    def "Verify that InvalidCertificateException is thrown if end entity certificate is not yet valid"(){
        setup:
        def certChain = genCertChain([[type: "endentity", name: "some endEntity", startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "hours"],
                                      [type: "subca", name: "some subca", startTime: "2019-07-01 14:01:02", duration: 1, durationUnit: "years"],
                                      [type: "rootca", name: "some rootca", startTime: "2019-06-01 14:01:02", duration: 2, durationUnit: "years"]])
        when:
        validator.validateTime(toDate("2019-08-01 14:01:01"), certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid certificate in chain, not yet valid."
    }

    def "Verify that InvalidCertificateException is thrown if sub ca certificate is not yet valid"(){
        setup:
        def certChain = genCertChain([[type: "endentity", name: "some endEntity", startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "hours"],
                                      [type: "subca", name: "some subca", startTime: "2019-09-01 14:01:02", duration: 1, durationUnit: "years"],
                                      [type: "rootca", name: "some rootca", startTime: "2019-06-01 14:01:02", duration: 2, durationUnit: "years"]])
        when:
        validator.validateTime(toDate("2019-08-01 15:01:01"), certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid certificate in chain, not yet valid."
    }

    def "Verify that InvalidCertificateException is thrown if sub ca certificate has expired"(){
        setup:
        def certChain = genCertChain([[type: "endentity", name: "some endEntity", startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "hours"],
                                      [type: "subca", name: "some subca", startTime: "2019-07-01 14:01:02", duration: 1, durationUnit: "hours"],
                                      [type: "rootca", name: "some rootca", startTime: "2019-06-01 14:01:02", duration: 2, durationUnit: "years"]])
        when:
        validator.validateTime(toDate("2019-08-01 15:01:01"), certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Expired certificate exists in chain."
    }


    def "Verify that InvalidCertificateException is thrown if root ca certificate is not yet valid"(){
        setup:
        def certChain = genCertChain([[type: "endentity", name: "some endEntity", startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "hours"],
                                      [type: "subca", name: "some subca", startTime: "2019-07-01 14:01:02", duration: 1, durationUnit: "years"],
                                      [type: "rootca", name: "some rootca", startTime: "2019-09-01 14:01:02", duration: 2, durationUnit: "years"]])
        when:
        validator.validateTime(toDate("2019-08-01 15:01:01"), certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid certificate in chain, not yet valid."
    }

    def "Verify that InvalidCertificateException is thrown if root ca certificate has expired"(){
        setup:
        def certChain = genCertChain([[type: "endentity", name: "some endEntity", startTime: "2019-08-01 14:01:02", duration: 24, durationUnit: "hours"],
                                      [type: "subca", name: "some subca", startTime: "2019-07-01 14:01:02", duration: 1, durationUnit: "years"],
                                      [type: "rootca", name: "some rootca", startTime: "2019-06-01 14:01:02", duration: 2, durationUnit: "hours"]])
        when:
        validator.validateTime(toDate("2019-08-01 15:01:01"), certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Expired certificate exists in chain."
    }

    @Unroll
    def "Verify that durationAsMS #durationUnit with value #value returns expected result #result"(){
        expect:
        validator.durationAsMS(new Duration(durationUnit, value)) == result
        where:
        durationUnit     | value       | result
        milliseconds     | 5           | 5
        seconds          | 7           | 7 * 1000L
        minutes          | 15          | 15 * 60 * 1000L
        hours            | 2           | 2 * 60 * 60 * 1000L
        sixtyHours       | 3           | 3 * 60 * 60 * 60 * 1000L
    }

    def "Verify that durationAsMS throws InvalidCertificateException if duration unit is specified in microseconds"(){
        when:
        validator.durationAsMS(new Duration(microseconds,10))
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid validity period in certificate, duration unit of microseconds is not supported."
    }

    def "Verify that toEndDate calculates expected date for duration unit in years"(){
        expect:
        validator.toEndDate(toDate("2017-06-11 02:02:02"), new Duration(years, 2)) == toDate("2019-06-11 02:02:02")
    }

    @Unroll
    def "Verify that toEndDate calculates expected date for duration unit #durationUnit"(){
        expect:
        validator.toEndDate(new Date(1000L), new Duration(durationUnit, 1)).time == expected
        where:
        durationUnit   | expected
        milliseconds   | 1001L
        seconds        | 1000 + 1000
        minutes        | 1000 + (60 * 1000)
        hours          | 1000 + (60 * 60 * 1000)
        sixtyHours     | 1000 + (60 * 60 * 60 * 1000)
    }

    Certificate[] genCertChain(List specification){
        Certificate[] certChain = new Certificate[specification.size()]
        ETSIAuthorityCertGenerator authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager)
        ETSIEnrollmentCredentialGenerator enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(cryptoManager)
        KeyPair keys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)


        for(int i=specification.size()-1;i>=0;i--){
            Map m = specification[i]
            def validityPeriod = genValidityPeriod(m)
            switch (m.type){
                case "rootca":
                    certChain[i] = authorityCertGenerator.genRootCA((String) m.name, // caName
                            validityPeriod, //ValidityPeriod
                            null, //GeographicRegion
                            3, // minChainDepth
                            -1, // chainDepthRange
                            Hex.decode("0138"), // cTLServiceSpecificPermissions, 2 octets
                            Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                            keys.getPublic(), // signPublicKey
                            keys.getPrivate(), // signPrivateKey
                            SymmAlgorithm.aes128Ccm, // symmAlgorithm
                            BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                            keys.getPublic())
                    break
                case "subca":
                    certChain[i] = authorityCertGenerator.genEnrollmentCA((String) m.name, // CA Name
                            validityPeriod,
                            null,  //GeographicRegion
                            new SubjectAssurance(1,3), // subject assurance (optional)
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
                case "endentity":
                    certChain[i] = enrollmentCredentialCertGenerator.genEnrollCredential(
                            (String) m.name, // unique identifier name
                            validityPeriod,
                            null,
                            Hex.decode("01C0"), //SSP data set in SecuredCertificateRequestService appPermission, two byte, for example: 0x01C0
                            1, // assuranceLevel
                            3, // confidenceLevel
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

    private SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")

    private toDate(String dateString){
        return simpleDateFormat.parse(dateString)
    }

    private ValidityPeriod genValidityPeriod(Map m){
        Date startDate = simpleDateFormat.parse((String) m.startTime)
        Duration duration = new Duration(Duration.DurationChoices.valueOf((String) m.durationUnit), (int) m.duration)
        return new ValidityPeriod(new Time32(startDate), duration)
    }
}
