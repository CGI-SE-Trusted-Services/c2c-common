package org.certificateservices.custom.c2x.etsits102941.v131.util

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.custom.c2x.common.crypto.CryptoManager
import org.certificateservices.custom.c2x.common.validator.CertificateRevokedException
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CrlEntry
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CRL
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedCrl
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941SecureDataGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSISecuredDataGenerator
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64
import org.certificateservices.custom.c2x.ieee1609dot2.validator.BasePermissionValidatorSpec
import spock.lang.Shared
import spock.lang.Specification

import java.security.PrivateKey
import java.security.Security

/**
 * Unit tests for Etsi102941CRLHelper
 *
 * @author Philip Vendil
 */
class Etsi102941CRLHelperSpec extends Specification {

    @Shared Etsi102941CRLHelper helper
    @Shared TestPKI1 testPKI1
    static CryptoManager cryptoManager
    static ETSITS102941MessagesCaGenerator etsits102941MessagesCaGenerator

    static{
        Security.addProvider(new BouncyCastleProvider())
        ETSITS102941SecureDataGenerator etsiSecuredDataGenerator =  new ETSITS102941SecureDataGenerator(ETSISecuredDataGenerator.DEFAULT_VERSION, BasePermissionValidatorSpec.cryptoManager, HashAlgorithm.sha256, Signature.SignatureChoices.ecdsaNistP256Signature);
        etsits102941MessagesCaGenerator = new ETSITS102941MessagesCaGenerator(etsiSecuredDataGenerator)
        cryptoManager = BasePermissionValidatorSpec.cryptoManager
    }

    def setupSpec(){
        testPKI1 = new TestPKI1()
        helper = new Etsi102941CRLHelper()
    }


    def "Verify that getToBeSignedCrl returns inner ToBeSignedCrl structure"(){
        expect:
        helper.getToBeSignedCrl(testPKI1.rootCA1Crl) instanceof ToBeSignedCrl
    }

    def "Verify that getToBeSignedCrl throws IOException if inner structure does not contain any ToBeSignedCrl."(){
        setup:
        EtsiTs102941CRL crl = new EtsiTs102941CRL(testPKI1.fullTlmCtl)
        when:
        helper.getToBeSignedCrl(crl)
        then:
        def e = thrown IOException
        e.message == "Invalid data structure, verify that data is of type certificateRevocationList."
    }

    def "Verify that checkRevoked throws CertificateRevokedException for certificates included in the list"(){
        when:
        helper.checkRevoked(helper.getToBeSignedCrl(testPKI1.rootCA1Crl), testPKI1.rca1_ea1.asHashedId8(cryptoManager))
        then:
        def e = thrown CertificateRevokedException
        e.message =~ "Certificate HashedId8"
        e.message =~ "is included in CRL."
        when:
        helper.checkRevoked(helper.getToBeSignedCrl(testPKI1.rootCA1Crl), testPKI1.rca1_aa1.asHashedId8(cryptoManager))
        then:
        e = thrown CertificateRevokedException
        e.message =~ "Certificate HashedId8"
        e.message =~ "is included in CRL."
    }

    def "Verify that checkRevoked does not throw CertificateRevokedException for certificates is not included in the list"(){
        when:
        helper.checkRevoked(helper.getToBeSignedCrl(testPKI1.rootCA1Crl), testPKI1.rca1_ea2.asHashedId8(cryptoManager))
        then:
        true
    }

    static EtsiTs102941CRL genCRL(Map m){
        def cryptoManager = BasePermissionValidatorSpec.cryptoManager
        Time32 thisUpdate = new Time32(TestPKI1.simpleDateFormat.parse(m.thisUpdate))
        Time32 nextUpdate = new Time32(TestPKI1.simpleDateFormat.parse(m.nextUpdate))
        CrlEntry[] crlEntries = m.entries != null ? m.entries.collect { EtsiTs103097Certificate it -> new CrlEntry(it.asHashedId8(cryptoManager).data)} as CrlEntry[] : [] as CrlEntry[]


        ToBeSignedCrl toBeSignedCrl = new ToBeSignedCrl(Version.V1, thisUpdate, nextUpdate, crlEntries)
         return etsits102941MessagesCaGenerator.genCertificateRevocationListMessage(new Time64(new Date()), toBeSignedCrl,
                    (EtsiTs103097Certificate[]) m.signerChain, (PrivateKey) m.signerKey.private)
    }
}
