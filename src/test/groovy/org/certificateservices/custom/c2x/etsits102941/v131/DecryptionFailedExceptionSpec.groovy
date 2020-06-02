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
package org.certificateservices.custom.c2x.etsits102941.v131

import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver
import spock.lang.Specification

import javax.crypto.SecretKey

/**
 * Unit tests for DecryptionFailedException
 */
class DecryptionFailedExceptionSpec extends Specification {

    byte[] requestHash = [1,2,3] as byte[]

    def "Verify that constructor populates fields correctly"(){
        setup:
        def key = Mock(SecretKey)
        def receiver = Mock(Receiver)
        def cause = new IOException()
        when:
        def e1 = new DecryptionFailedException("SomeMessage", cause)
        then:
        e1.message == "SomeMessage"
        e1.cause == cause
        e1.getSecretKey() == null

        when:
        def e2 = new DecryptionFailedException("SomeMessage", cause ,key, requestHash, receiver)
        then:
        e2.message  == "SomeMessage"
        e2.cause == cause
        e2.getReceiver() == receiver
        e2.getSecretKey() == key
        e2.getRequestHash() == requestHash
    }
}