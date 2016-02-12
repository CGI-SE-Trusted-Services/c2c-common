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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IValue;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for IValue
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class IValueSpec extends BaseStructSpec {

	@Unroll
	def "Verify constructors"(){
		when:
		def e1 = new IValue(10)
		
		then:
		serializeToHex(e1) == "000a"
		
		when:
		IValue e2 = deserializeFromHex(new IValue(), "000a")
		
		then:
		e2.getValueAsLong() == 10
	}
		
	
	def "Verify IValue toString"(){
		expect:
		new IValue(1000).toString() == "IValue [1000]"
	}

}
