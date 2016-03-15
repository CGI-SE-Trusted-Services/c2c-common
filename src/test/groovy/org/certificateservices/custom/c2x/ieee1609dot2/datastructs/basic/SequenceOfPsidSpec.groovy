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

import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfPsid;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all SequenceOfPsid class
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfPsidSpec extends BaseStructSpec {

	Psid id1 = new Psid(101)
	Psid id2 = new Psid(64321)
	
	
	def "Verify that SequenceOfPsid is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfPsid(),"0102016502fb41")
		then:
		u1.getSequenceValues()[0].getValueAsLong() == 101
		u1.getSequenceValues()[1].getValueAsLong() == 64321
		when:
		def u2 = new SequenceOfPsid([id1,id2] as Psid[])
		then:
		u2.getSequenceValues()[0].getValueAsLong() == 101
		u2.getSequenceValues()[1].getValueAsLong() == 64321
		
		
		when:
		def u3 = new SequenceOfPsid([id1,id2])
		then:
		u3.getSequenceValues()[0].getValueAsLong() == 101
		u3.getSequenceValues()[1].getValueAsLong() == 64321
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfPsid([id1,id2]).toString() == "SequenceOfPsid [[101(65)],[64321(fb41)]]"
		new SequenceOfPsid().toString() == "SequenceOfPsid []"
		new SequenceOfPsid([id1]).toString() == "SequenceOfPsid [[101(65)]]"
		
	
	}
	
	


}
