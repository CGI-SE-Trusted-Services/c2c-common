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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId10
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8

import java.security.MessageDigest

/**
 * Test for all HashedIdX classes
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class AllHashedIdSpec extends BaseStructSpec {
	
	byte[] fullHashValue;
	byte[] referenseHash = Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	def setup(){
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update("Some Text to be Hashed".getBytes("UTF-8"))
		fullHashValue = md.digest()
		
	}

	
	def "Verify that HashedId3 only stores the 3 least significant bytes"(){
		when:
		HashedId3 h1 = new HashedId3(fullHashValue)
		then:
		h1.getHashedId() == h1.getData(); // verify the methods returns the same data
		h1.getHashedId().length == 3
		h1.getHashLength() == 3
		serializeToHex(h1) == "944d99"
		
		when:
		HashedId3 h2 = deserializeFromHex(new HashedId3(), "944d99")
		then:
		h2.getHashedId() == h1.getHashedId()

		when:
		HashedId3 h3 = new HashedId3(referenseHash)
		then:
		serializeToHex(h3) == "52b855"
	}
	
	def "Verify that HashedId8 only stores the 8 least significant bytes"(){
		when:
		HashedId8 h1 = new HashedId8(fullHashValue)
		then:
		h1.getHashedId() == h1.getData(); // verify the methods returns the same data
		h1.getHashedId().length == 8
		h1.getHashLength() == 8
		serializeToHex(h1) == "d778056af1944d99"
		
		when:
		HashedId8 h2 = deserializeFromHex(new HashedId8(), "d778056af1944d99")
		then:
		h2.getHashedId() == h1.getHashedId()

		when:
		HashedId8 h3 = new HashedId8(referenseHash)
		then:
		serializeToHex(h3) == "a495991b7852b855"
	}
	
	def "Verify that HashedId10 only stores the 10 least significant bytes"(){
		when:
		HashedId10 h1 = new HashedId10(fullHashValue)
		then:
		h1.getHashedId() == h1.getData(); // verify the methods returns the same data
		h1.getHashedId().length == 10
		h1.getHashLength() == 10
		serializeToHex(h1) == "9187d778056af1944d99"
		
		when:
		HashedId10 h2 = deserializeFromHex(new HashedId10(), "9187d778056af1944d99")
		then:
		h2.getHashedId() == h1.getHashedId()

		when:
		HashedId10 h3 = new HashedId10(referenseHash)
		then:
		serializeToHex(h3) == "934ca495991b7852b855"
	}

	def "Verify toString"(){
		expect:
		new HashedId3(fullHashValue).toString() == "HashedId3 [944d99]"
		new HashedId8(fullHashValue).toString() == "HashedId8 [d778056af1944d99]"
		new HashedId10(fullHashValue).toString() == "HashedId10 [9187d778056af1944d99]"
	}
}
