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
package org.certificateservices.custom.c2x.ieee1609dot2.generator

import org.certificateservices.custom.c2x.common.BadArgumentException
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateType

import java.security.KeyPair

/**
 * Unit tests for CertChainBuilder
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class CertChainBuilderSpec extends BaseCertGeneratorSpec  {

    CertChainBuilder certChainBuilder

    def setup(){
        certChainBuilder = new CertChainBuilder(cryptoManager)
    }

    def "Verify that buildCertStore() generates certificate store maps correctly and buildChain generates correct certificate chain"(){
        setup:
        def alg = PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
        KeyPair rootCAKeys1 = cryptoManager.generateKeyPair(alg)
        Certificate rootCA1 = genRootCA(rootCAKeys1)
        HashedId8 rootCA1Id = certChainBuilder.getCertID(rootCA1)
        KeyPair rootCAKeys2 = cryptoManager.generateKeyPair(alg)
        Certificate rootCA2 = genRootCA(rootCAKeys2)
        HashedId8 rootCA2Id = certChainBuilder.getCertID(rootCA2)
        KeyPair enrollCAKeys1 = cryptoManager.generateKeyPair(alg)
        Certificate enrollCA1 = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys1, rootCAKeys1, rootCA1)
        HashedId8 enrollCA1Id = certChainBuilder.getCertID(enrollCA1)
        KeyPair enrollCAKeys2 = cryptoManager.generateKeyPair(alg)
        Certificate enrollCA2 = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys2, rootCAKeys2, rootCA2)
        HashedId8 enrollCA2Id = certChainBuilder.getCertID(enrollCA2)
        KeyPair enrollCertKeys1 = cryptoManager.generateKeyPair(alg)
        Certificate enrollCert1 = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys1, enrollCAKeys1.publicKey, enrollCAKeys1.privateKey, enrollCA1)
        HashedId8 enrollCert1Id = certChainBuilder.getCertID(enrollCert1)
        KeyPair enrollCertKeys2 = cryptoManager.generateKeyPair(alg)
        Certificate enrollCert2 = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys2, enrollCAKeys2.publicKey, enrollCAKeys2.privateKey, enrollCA2)
        HashedId8 enrollCert2Id = certChainBuilder.getCertID(enrollCert2)

        when: "Verify that buildCertStore generates correct stores"
        Map<HashedId8, Certificate> trustStore = sdg.buildCertStore([rootCA1, rootCA2] as Certificate[])
        Map<HashedId8, Certificate> certStore1 = sdg.buildCertStore([enrollCA1, enrollCA2, enrollCert1] as Certificate[])
        Map<HashedId8, Certificate> certStore2 = sdg.buildCertStore([enrollCA1, enrollCA2, rootCA2] as Certificate[])
        Map<HashedId8, Certificate> signedDataStore1 = sdg.buildCertStore([enrollCA2, enrollCert2] as Certificate[])
        Map<HashedId8, Certificate> signedDataStore2 = sdg.buildCertStore([enrollCert2] as Certificate[])
        then:
        trustStore.size() == 2
        trustStore.get(rootCA1Id) == rootCA1
        trustStore.get(rootCA2Id) == rootCA2

        certStore1.size() == 3
        certStore1.get(enrollCA1Id) == enrollCA1
        certStore1.get(enrollCA2Id) == enrollCA2
        certStore1.get(enrollCert1Id) == enrollCert1


        when: "Verify that buildChain constructs a correct chain for a root ca only chain"
        Certificate[] c = certChainBuilder.buildChain(rootCA2Id, signedDataStore1, certStore1, trustStore)
        then:
        c.length == 1
        c[0] == rootCA2

        when: "Verify that buildChain constructs a chain from all three stores"
        c = certChainBuilder.buildChain(enrollCert2Id, signedDataStore1, certStore1, trustStore)
        then:
        c.length == 3
        c[0] == enrollCert2
        c[1] == enrollCA2
        c[2] == rootCA2

        when: "Verify that illegal argument is found if signing certificate cannot be found"
        certChainBuilder.buildChain(enrollCert2Id, [:], [:], [:])
        then:
        thrown BadArgumentException

        when: "Verify that illegal argument is found if root certificate cannot be found as trust anchor"
        certChainBuilder.buildChain(enrollCert2Id, signedDataStore1, certStore2, [:])
        then:
        thrown BadArgumentException

        when: "Verify that illegal argument is found if intermediate certificate cannot be found"
        certChainBuilder.buildChain(enrollCert2Id, signedDataStore2, [:], trustStore)
        then:
        thrown BadArgumentException
    }

    def "Verify that findFromStores finds certificate from stores"(){
        setup:
        KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256)
        Certificate rootCA = genRootCA(rootCAKeys)
        KeyPair enrollCAKeys = cryptoManager.generateKeyPair(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256)
        Certificate enrollCA = genEnrollCA(CertificateType.implicit, PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256, enrollCAKeys, rootCAKeys, rootCA)
        HashedId8 certId = certChainBuilder.getCertID(enrollCA)
        HashedId8 rootCertId = certChainBuilder.getCertID(rootCA)
        expect:
        certChainBuilder.findFromStores(certId, [(certId):enrollCA], [:], [:]) == enrollCA
        certChainBuilder.findFromStores(certId, [:],[(certId):enrollCA], [:]) == enrollCA
        certChainBuilder.findFromStores(rootCertId, [:],[:],[(rootCertId):rootCA]) == rootCA
        certChainBuilder.findFromStores(certId, [:],[:],[:]) == null

        when: "Verify that implicit trust ancor generates BadArgumentException"
        certChainBuilder.findFromStores(certId, [:],[:],[(certId):enrollCA])

        then:
        thrown BadArgumentException

    }

    def "Verify getCertID generates a correct HashedId8 for explicit certificate with SHA256"(){
        setup:
        KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256)
        Certificate rootCA = genRootCA(rootCAKeys)

        when:
        HashedId8 certId = certChainBuilder.getCertID(rootCA)
        then:
        certId == new HashedId8(cryptoManager.digest(rootCA.getEncoded(), HashAlgorithm.sha256))
    }

    def "Verify getCertID generates a correct HashedId8 for explicit certificate with SHA384"(){
        setup:
        KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256)
        Certificate rootCA = genRootCA(rootCAKeys, PublicVerificationKey.PublicVerificationKeyChoices.ecdsaBrainpoolP384r1)

        when:
        HashedId8 certId = certChainBuilder.getCertID(rootCA)
        then:
        certId == new HashedId8(cryptoManager.digest(rootCA.getEncoded(), HashAlgorithm.sha384))
    }

    def "Verify getCertID generated a correct HashedId8 for implicit certificate"(){
        setup:
        KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256)
        Certificate rootCA = genRootCA(rootCAKeys, PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256)
        KeyPair enrollCAKeys = cryptoManager.generateKeyPair(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256)
        Certificate enrollCA = genEnrollCA(CertificateType.implicit, PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256, enrollCAKeys, rootCAKeys, rootCA)
        when:
        when:
        HashedId8 certId = certChainBuilder.getCertID(enrollCA)
        then:
        certId == new HashedId8(cryptoManager.digest(enrollCA.getEncoded(), HashAlgorithm.sha256))
    }
}
