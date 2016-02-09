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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfIdentifiedRegion;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all SequenceOfIdentifiedRegion class
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfIdentifiedRegionSpec extends BaseStructSpec {

	IdentifiedRegion ir1 = new IdentifiedRegion(IdentifiedRegionChoices.countryOnly, new CountryOnly(4))
	IdentifiedRegion ir2 = new IdentifiedRegion(IdentifiedRegionChoices.countryOnly, new CountryOnly(5))
	
	
	def "Verify that SequenceOfIdentifiedRegion is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfIdentifiedRegion(),"0102800004800005")
		then:
		u1.getSequenceValues()[0].getValue().getValueAsLong() == 4
		u1.getSequenceValues()[1].getValue().getValueAsLong() == 5
		when:
		def u2 = new SequenceOfIdentifiedRegion([ir1,ir2] as IdentifiedRegion[])
		then:
		u2.getSequenceValues()[0].getValue().getValueAsLong() == 4
		u2.getSequenceValues()[1].getValue().getValueAsLong() == 5
		
		when:
		def u3 = new SequenceOfIdentifiedRegion([ir1,ir2])
		then:
		u3.getSequenceValues()[0].getValue().getValueAsLong() == 4
		u3.getSequenceValues()[1].getValue().getValueAsLong() == 5
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfIdentifiedRegion([ir1,ir2]).toString() == "SequenceOfIdentifiedRegion [[CountryOnly [4]],[CountryOnly [5]]]"
		new SequenceOfIdentifiedRegion().toString() == "SequenceOfIdentifiedRegion []"
		new SequenceOfIdentifiedRegion([ir1]).toString() == "SequenceOfIdentifiedRegion [[CountryOnly [4]]]"
		
	
	}
	
	


}
