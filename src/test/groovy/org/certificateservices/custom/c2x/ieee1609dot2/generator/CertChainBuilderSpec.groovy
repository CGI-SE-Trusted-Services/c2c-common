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
import org.certificateservices.custom.c2x.common.CertStore
import org.certificateservices.custom.c2x.common.MapCertStore
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
    


    def "Verify that buildCertStore() generates certificate store maps correctly and buildChain generates correct certificate chain"(){
        setup:
        def alg = PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
        KeyPair rootCAKeys1 = cryptoManager.generateKeyPair(alg)
        Certificate rootCA1 = genRootCA(rootCAKeys1)
        HashedId8 rootCA1Id = CertChainBuilder.getCertID(cryptoManager,rootCA1)
        KeyPair rootCAKeys2 = cryptoManager.generateKeyPair(alg)
        Certificate rootCA2 = genRootCA(rootCAKeys2)
        HashedId8 rootCA2Id = CertChainBuilder.getCertID(cryptoManager, rootCA2)
        KeyPair enrollCAKeys1 = cryptoManager.generateKeyPair(alg)
        Certificate enrollCA1 = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys1, rootCAKeys1, rootCA1)
        HashedId8 enrollCA1Id = CertChainBuilder.getCertID(cryptoManager, enrollCA1)
        KeyPair enrollCAKeys2 = cryptoManager.generateKeyPair(alg)
        Certificate enrollCA2 = genEnrollCA(CertificateType.explicit, alg, enrollCAKeys2, rootCAKeys2, rootCA2)
        HashedId8 enrollCA2Id = CertChainBuilder.getCertID(cryptoManager, enrollCA2)
        KeyPair enrollCertKeys1 = cryptoManager.generateKeyPair(alg)
        Certificate enrollCert1 = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys1, enrollCAKeys1.publicKey, enrollCAKeys1.privateKey, enrollCA1)
        HashedId8 enrollCert1Id = CertChainBuilder.getCertID(cryptoManager, enrollCert1)
        KeyPair enrollCertKeys2 = cryptoManager.generateKeyPair(alg)
        Certificate enrollCert2 = genEnrollCert(CertificateType.explicit, alg, enrollCertKeys2, enrollCAKeys2.publicKey, enrollCAKeys2.privateKey, enrollCA2)
        HashedId8 enrollCert2Id = CertChainBuilder.getCertID(cryptoManager, enrollCert2)
        CertStore empty = new MapCertStore([:])

        when: "Verify that buildCertStore generates correct stores"
        CertStore trustStore = sdg.buildCertStore([rootCA1, rootCA2] as Certificate[])
        CertStore certStore1 = sdg.buildCertStore([enrollCA1, enrollCA2, enrollCert1] as Certificate[])
        CertStore certStore2 = sdg.buildCertStore([enrollCA1, enrollCA2, rootCA2] as Certificate[])
        CertStore signedDataStore1 = sdg.buildCertStore([enrollCA2, enrollCert2] as Certificate[])
        CertStore signedDataStore2 = sdg.buildCertStore([enrollCert2] as Certificate[])
        then:
        trustStore.map.size() == 2
        trustStore.get(rootCA1Id) == rootCA1
        trustStore.get(rootCA2Id) == rootCA2

        certStore1.map.size() == 3
        certStore1.get(enrollCA1Id) == enrollCA1
        certStore1.get(enrollCA2Id) == enrollCA2
        certStore1.get(enrollCert1Id) == enrollCert1


        when: "Verify that buildChain constructs a correct chain for a root ca only chain"
        Certificate[] c = CertChainBuilder.buildChain(cryptoManager, rootCA2Id, signedDataStore1, certStore1, trustStore)
        then:
        c.length == 1
        c[0] == rootCA2

        when: "Verify that buildChain constructs a chain from all three stores"
        c = CertChainBuilder.buildChain(cryptoManager, enrollCert2Id, signedDataStore1, certStore1, trustStore)
        then:
        c.length == 3
        c[0] == enrollCert2
        c[1] == enrollCA2
        c[2] == rootCA2

        when: "Verify that illegal argument is found if signing certificate cannot be found"
        CertChainBuilder.buildChain(cryptoManager, enrollCert2Id, empty, empty, empty)
        then:
        thrown BadArgumentException

        when: "Verify that illegal argument is found if root certificate cannot be found as trust anchor"
        CertChainBuilder.buildChain(cryptoManager, enrollCert2Id, signedDataStore1, certStore2, empty)
        then:
        thrown BadArgumentException

        when: "Verify that illegal argument is found if intermediate certificate cannot be found"
        CertChainBuilder.buildChain(cryptoManager, enrollCert2Id, signedDataStore2, empty, trustStore)
        then:
        thrown BadArgumentException
    }

    def "Verify that findFromStores finds certificate from stores"(){
        setup:
        KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256)
        Certificate rootCA = genRootCA(rootCAKeys)
        KeyPair enrollCAKeys = cryptoManager.generateKeyPair(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256)
        Certificate enrollCA = genEnrollCA(CertificateType.implicit, PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256, enrollCAKeys, rootCAKeys, rootCA)
        HashedId8 certId = CertChainBuilder.getCertID(cryptoManager, enrollCA)
        HashedId8 rootCertId = CertChainBuilder.getCertID(cryptoManager, rootCA)
        MapCertStore empty = new MapCertStore([:])
        expect:
        CertChainBuilder.findFromStores(cryptoManager, certId, new MapCertStore([(certId):enrollCA]), empty, empty) == enrollCA
        CertChainBuilder.findFromStores(cryptoManager, certId, empty,new MapCertStore([(certId):enrollCA]), empty) == enrollCA
        CertChainBuilder.findFromStores(cryptoManager, rootCertId, empty,empty,new MapCertStore([(rootCertId):rootCA])) == rootCA
        CertChainBuilder.findFromStores(cryptoManager, certId, empty,empty,empty) == null

        when: "Verify that implicit trust anchor generates BadArgumentException"
        CertChainBuilder.findFromStores(cryptoManager, certId, empty,empty,new MapCertStore([(certId):enrollCA]))

        then:
        thrown BadArgumentException

    }

    def "Verify getCertID generates a correct HashedId8 for explicit certificate with SHA256"(){
        setup:
        KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256)
        Certificate rootCA = genRootCA(rootCAKeys)

        when:
        HashedId8 certId = CertChainBuilder.getCertID(cryptoManager, rootCA)
        then:
        certId == new HashedId8(cryptoManager.digest(rootCA.getEncoded(), HashAlgorithm.sha256))
    }

    def "Verify getCertID generates a correct HashedId8 for explicit certificate with SHA384"(){
        setup:
        KeyPair rootCAKeys = cryptoManager.generateKeyPair(PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256)
        Certificate rootCA = genRootCA(rootCAKeys, PublicVerificationKey.PublicVerificationKeyChoices.ecdsaBrainpoolP384r1)

        when:
        HashedId8 certId = CertChainBuilder.getCertID(cryptoManager,rootCA)
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
        HashedId8 certId = CertChainBuilder.getCertID(cryptoManager,enrollCA)
        then:
        certId == new HashedId8(cryptoManager.digest(enrollCA.getEncoded(), HashAlgorithm.sha256))
    }
}
