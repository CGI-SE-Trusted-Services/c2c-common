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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec

/**
 * Test for all SequenceOHashedId8 class
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfHashedId8Spec extends BaseStructSpec {

	HashedId8 hi1 = new HashedId8(Hex.decode("001122334455667788"))
	HashedId8 hi2 = new HashedId8(Hex.decode("001122334455667799"))
	
	def "Verify that SequenceOfHashedId3 is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfHashedId8(),"010211223344556677881122334455667799")
		then:
		serializeToHex(u1.getSequenceValues()[0])  == "1122334455667788"
		serializeToHex(u1.getSequenceValues()[1])  == "1122334455667799"
		when:
		def u2 = new SequenceOfHashedId8([hi1,hi2] as HashedId8[])
		then:
		serializeToHex(u2.getSequenceValues()[0])  == "1122334455667788"
		serializeToHex(u2.getSequenceValues()[1])  == "1122334455667799"
		when:
		def u3 = new SequenceOfHashedId8([hi1,hi2])
		then:
		serializeToHex(u3.getSequenceValues()[0])  == "1122334455667788"
		serializeToHex(u3.getSequenceValues()[1])  == "1122334455667799"
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfHashedId8([hi1,hi2]).toString() == "SequenceOfHashedId8 [1122334455667788,1122334455667799]"
		new SequenceOfHashedId8().toString() == "SequenceOfHashedId8 []"
		new SequenceOfHashedId8([hi1]).toString() == "SequenceOfHashedId8 [1122334455667788]"
	}
}
