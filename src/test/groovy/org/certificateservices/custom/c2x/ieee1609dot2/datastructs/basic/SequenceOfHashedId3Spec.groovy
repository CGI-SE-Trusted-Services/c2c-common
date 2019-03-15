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
 * Test for all SequenceOHashedId3 class
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfHashedId3Spec extends BaseStructSpec {

	HashedId3 hi1 = new HashedId3(Hex.decode("abce881272"))
	HashedId3 hi2 = new HashedId3(Hex.decode("abce883221"))
	
	def "Verify that SequenceOfHashedId3 is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfHashedId3(),"0102881272883221")
		then:
		serializeToHex(u1.getSequenceValues()[0])  == "881272"
		serializeToHex(u1.getSequenceValues()[1])  == "883221"
		when:
		def u2 = new SequenceOfHashedId3([hi1,hi2] as HashedId3[])
		then:
		serializeToHex(u2.getSequenceValues()[0])  == "881272"
		serializeToHex(u2.getSequenceValues()[1])  == "883221"
		
		when:
		def u3 = new SequenceOfHashedId3([hi1,hi2])
		then:
		serializeToHex(u3.getSequenceValues()[0])  == "881272"
		serializeToHex(u3.getSequenceValues()[1])  == "883221"
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfHashedId3([hi1,hi2]).toString() == "SequenceOfHashedId3 [881272,883221]"
		new SequenceOfHashedId3().toString() == "SequenceOfHashedId3 []"
		new SequenceOfHashedId3([hi1]).toString() == "SequenceOfHashedId3 [881272]"
	}
}
