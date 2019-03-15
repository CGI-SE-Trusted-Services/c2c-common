package org.certificateservices.custom.c2x.common.crypto

import spock.lang.Specification
import spock.lang.Unroll

// TODO
class AlgorithmSpec extends Specification {

    @Unroll
    def "Verify that expected field size is return for signature #signature"(){
        expect:
        signature.fieldSize == expectedFieldSize
        where:
        signature                                | expectedFieldSize
        Algorithm.Signature.ecdsaNistP256        | 32
        Algorithm.Signature.ecdsaBrainpoolP256r1 | 32
        Algorithm.Signature.ecdsaBrainpoolP384r1 | 48
    }
}
