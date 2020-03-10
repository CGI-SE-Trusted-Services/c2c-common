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
import org.certificateservices.custom.c2x.common.BadArgumentException
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CircularRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryAndRegions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryAndSubregions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Latitude
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Longitude
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.RegionAndSubregions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfIdentifiedRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfRegionAndSubregions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfUint16
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfUint8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.TwoDLocation
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint16
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import java.security.KeyPair

/**
 * Unit tests for CountryOnlyRegionValidator
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class CountryOnlyRegionValidatorSpec extends Specification {


    CountryOnlyRegionValidator validator = new CountryOnlyRegionValidator()
    @Shared Ieee1609Dot2CryptoManager cryptoManager

    def setupSpec(){
        cryptoManager = new DefaultCryptoManager()
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"))
    }

    def "Verify a valid certificate chain in whole world is accepted"(){
        setup:

        Certificate[] certChain = genCertChain([[type: "endentity", name: "someendentity", countries: null],
                      [type: "subca", name: "subca", countries: null],
                      [type: "rootca", name: "rootca", countries: null]])
        when: // When no acceptance region is specified
        validator.validateRegion(null,certChain)
        then:
        true
        when: // When a specific acceptance region is specified
        validator.validateRegion(GeographicRegion.generateRegionForCountrys([1]),certChain)
        then:
        true
    }

    def "Verify a valid certificate chain  where end entity cert is restricted to two countries, subca 4 countries, and root is world wide, matches list of accepted countries or throws InvalidCertificateException"(){
        setup:

        Certificate[] certChain = genCertChain([[type: "endentity", name: "someendentity", countries: [12,14]],
                                                [type: "subca", name: "subca", countries: [8,12,14,16]],
                                                [type: "rootca", name: "rootca", countries: null]])
        when: // When no acceptance region is specified
        validator.validateRegion(null,certChain)
        then:
        true
        when: // When a specific acceptance region is specified, that is specified in end entity certificate
        validator.validateRegion(GeographicRegion.generateRegionForCountrys([12]),certChain)
        then:
        true
        when: // Verify that InvalidCertificateException is thrown if certificate is not valid within region
        validator.validateRegion(GeographicRegion.generateRegionForCountrys([20]),certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid set of countryOnly ids in certificate."
    }

    def "Verify that an invalid cert chain where end entity certificate contains regions not accepted by subca throws InvalidCertificateException"(){
        setup:
        Certificate[] certChain = genCertChain([[type: "endentity", name: "someendentity", countries: [12,15]],
                                                [type: "subca", name: "subca", countries: [8,12,14,16]],
                                                [type: "rootca", name: "rootca", countries: null]])
        when:
        validator.validateRegion(null,certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid set of countryOnly ids in certificate."
        when:
        validator.validateRegion(GeographicRegion.generateRegionForCountrys([12]),certChain)
        then:
        e = thrown InvalidCertificateException
        e.message == "Invalid set of countryOnly ids in certificate."
        when:
        validator.validateRegion(GeographicRegion.generateRegionForCountrys([15]),certChain)
        then:
        e = thrown InvalidCertificateException
        e.message == "Invalid set of countryOnly ids in certificate."
        when:
        validator.validateRegion(GeographicRegion.generateRegionForCountrys([14]),certChain)
        then:
        e = thrown InvalidCertificateException
        e.message == "Invalid set of countryOnly ids in certificate."
    }

    def "Verify that an invalid cert chain where sub ca contains regions not accepted by root ca throws InvalidCertificateException"(){
        setup:
        Certificate[] certChain = genCertChain([[type: "endentity", name: "someendentity", countries: [12,14]],
                                                [type: "subca", name: "subca", countries: [8,12,14,16]],
                                                [type: "rootca", name: "rootca", countries: [12]]])
        when:
        validator.validateRegion(null,certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid set of countryOnly ids in certificate."
    }

    def "Verify that an valid cert chain where rootca have region specified is accepted, but throws InvalidCertificateException if checked against different region"(){
        setup:
        Certificate[] certChain = genCertChain([[type: "endentity", name: "someendentity", countries: [12,14]],
                                                [type: "subca", name: "subca", countries: [12,14,16]],
                                                [type: "rootca", name: "rootca", countries: [8,12,14,16]]])
        when:
        validator.validateRegion(null,certChain)
        then:
        true

        when:
        validator.validateRegion(GeographicRegion.generateRegionForCountrys([14]),certChain)
        then:
        true
        when:
        validator.validateRegion(GeographicRegion.generateRegionForCountrys([99]),certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid set of countryOnly ids in certificate."
    }

    def "Verify that InvalidCertificateException is thrown if top most certificate isn't a root certificate"(){
        setup:
        Certificate[] certChain = genCertChain([[type: "endentity", name: "someendentity", countries: [12,14]],
                                                [type: "subca", name: "subca", countries: [12,14,16]],
                                                [type: "rootca", name: "rootca", countries: [8,12,14,16]]])
        def certChainWithoutRoot = [certChain[0],certChain[1]] as Certificate[]
        when:
        validator.validateRegion(null,certChainWithoutRoot)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid certificate chain, top most certificate must be a root certificate."
    }

    def "Verify that rootca only chain available for whole world accepts any region"(){
        setup:
        Certificate[] certChain = genCertChain([[type: "rootca", name: "rootca", countries: null]])
        when:
        validator.validateRegion(null,certChain)
        then:
        true
        when:
        validator.validateRegion(GeographicRegion.generateRegionForCountrys([99]),certChain)
        then:
        true
    }

    def "Verify that rootca only chain with specified set of regions throws InvalidCertificateException for invalid regions"(){
        setup:
        Certificate[] certChain = genCertChain([[type: "rootca", name: "rootca", countries: [8,27]]])
        when:
        validator.validateRegion(null,certChain)
        then:
        true
        when:
        validator.validateRegion(GeographicRegion.generateRegionForCountrys([8]),certChain)
        then:
        true
        when:
        validator.validateRegion(GeographicRegion.generateRegionForCountrys([99]),certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid set of countryOnly ids in certificate."
    }

    @Unroll
    def "Verify that validateRegion throws BadArgumentException if checkRegion #desc"(){
        setup:
        Certificate[] certChain = genCertChain([[type: "rootca", name: "rootca", countries: [8,27]]])
        when:
        validator.validateRegion(region,certChain)
        then:
        def e = thrown BadArgumentException
        e.message == "Invalid argument, acceptedRegion must be of type identifiedRegion containing only countryOnly."
        where:
        desc                              | region
        "contains a CountryAndRegions"    | genRegion([useCountryAndRegion: true])
        "contains a CountryAndSubregions" | genRegion([useCountryAndSubregions: true])
        "contains a CircularRegion"       | genRegion([useCircularRegion: true])
    }


    def "Verify that validateRegion throws InvalidCertificateException if one of the checked certificates contains certificate that is not country only."(){
        setup:

        Certificate[] certChain = genCertChain([[type: "endentity", name: "someendentity", useCountryAndRegion: true],
                                                [type: "subca", name: "subca", countries: [12,14,16]],
                                                [type: "rootca", name: "rootca", countries: [8,12,14,16]]])
        when:
        validator.validateRegion(null,certChain)
        then:
        def e = thrown InvalidCertificateException
        e.message == "Invalid region in certificate, only identifiedRegion with sequence of country only is supported not countryAndRegions."
        when:
        certChain = genCertChain([[type: "endentity", name: "someendentity", countries: [12,14,16]],
                                                [type: "subca", name: "subca", useCountryAndSubregions: true],
                                                [type: "rootca", name: "rootca", countries: [8,12,14,16]]])

        validator.validateRegion(GeographicRegion.generateRegionForCountrys([8]),certChain)
        then:
        e = thrown InvalidCertificateException
        e.message == "Invalid region in certificate, only identifiedRegion with sequence of country only is supported not countryAndSubregions."
        when:
        certChain = genCertChain([[type: "endentity", name: "someendentity", countries: [12,14,16]],
                                  [type: "subca", name: "subca", countries: [12,14,16]],
                                  [type: "rootca", name: "rootca", useCircularRegion: true]])

        validator.validateRegion(GeographicRegion.generateRegionForCountrys([8]),certChain)
        then:
        e = thrown InvalidCertificateException
        e.message == "Invalid region in certificate, only identifiedRegion is supported not circularRegion."
    }



    Certificate[] genCertChain(List specification){
        Certificate[] certChain = new Certificate[specification.size()]
        ETSIAuthorityCertGenerator authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager)
        ETSIEnrollmentCredentialGenerator enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(cryptoManager)
        KeyPair keys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature)

        ValidityPeriod validityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 45);

        for(int i=specification.size()-1;i>=0;i--){
            Map m = specification[i]
            GeographicRegion region = genRegion(m)
            switch (m.type){
                case "rootca":
                    certChain[i] = authorityCertGenerator.genRootCA((String) m.name, // caName
                            validityPeriod, //ValidityPeriod
                            region, //GeographicRegion
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
                            region,  //GeographicRegion
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
                            region,
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
}
