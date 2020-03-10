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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert

import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType
import spock.lang.Unroll

/**
 * Test for EndEntityType
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EndEntityTypeSpec extends BaseStructSpec {
		
	@Unroll
	def "Verify that EndEntityType is correctly encoded #encoding for app #app and enroll #enroll"(){
		setup:
		String hexEncode = Integer.toHexString(Integer.parseInt(encoding,2))
		if(hexEncode.length() == 1){
			hexEncode = "0" + hexEncode;
		}
		when:
		EndEntityType ee = new EndEntityType(app,enroll)
		
		then:
		serializeToHex(ee) == hexEncode
		
		when:
		EndEntityType ee2 = deserializeFromHex(new EndEntityType(),hexEncode)
		
		then:
		ee2.isApp() == app
		ee2.isEnroll() == enroll
		
		where:
		app  | enroll   | encoding   
		true | true     | "11000000"
		false| true     | "1000000"
		true | false    | "10000000"

	}

	def "Verify that either app or enroll must be true"(){
		when:
		new EndEntityType(false,false)
		then:
		def e = thrown IOException
		e.message == "Invalid EndEntityType, either app or enroll flag must be set."
	}
	
	def "Verify toString"(){
		expect:
		new EndEntityType(true,false).toString() == "EndEntityType [app=true, enroll=false]"
	}
	

}
