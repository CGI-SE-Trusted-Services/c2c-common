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
package org.certificateservices.custom.c2x.etsits102941.v121.generator

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature
import spock.lang.Specification

import java.security.Security

/**
 * Unit tests for ETSITS102941SecureDataGenerator
 * @author Philip Vendil, p.vendil@cgi.com
 */
class ETSITS102941SecureDataGeneratorSpec extends Specification {

    def setupSpec(){
        Security.addProvider(new BouncyCastleProvider())
    }
    def "Verify constructor"(){
        when:
        ETSITS102941SecureDataGenerator g = new ETSITS102941SecureDataGenerator(2,Mock(Ieee1609Dot2CryptoManager), HashAlgorithm.sha384, Signature.SignatureChoices.ecdsaBrainpoolP384r1Signature)
        then:
        g.cryptoManager != null
    }

    // newEncryptedDataStructure is tested in ETSITS102941MessagesCaGenerator

}
