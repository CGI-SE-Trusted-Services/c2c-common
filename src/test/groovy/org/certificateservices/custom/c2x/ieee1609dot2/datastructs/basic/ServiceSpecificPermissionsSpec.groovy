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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions.ServiceSpecificPermissionsChoices
import spock.lang.Shared
import spock.lang.Unroll

/**
 * Test for ServiceSpecificPermissions
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class ServiceSpecificPermissionsSpec extends BaseStructSpec {
	
	@Shared byte[] x = new BigInteger(123).toByteArray()
	@Shared BitmapSsp bitmapSsp = new BitmapSsp(Hex.decode("121314"))
	
	@Unroll
	def "Verify that ServiceSpecificPermissions is correctly encoded for type #choice"(){
		when:
		def p = new ServiceSpecificPermissions(choice, value)
		
		then:
		serializeToHex(p) == encoding
		
		when:
		ServiceSpecificPermissions p2 = deserializeFromHex(new ServiceSpecificPermissions(), encoding)
		
		then:
		if(choice == ServiceSpecificPermissionsChoices.opaque){
			p2.getData() == x
		}
		if(choice == ServiceSpecificPermissionsChoices.bitmapSsp){
			p2.getBitmapSsp() == bitmapSsp
		}
		p2.choice == choice
		p2.type == choice
		choice.extension == extension
		
		where:
		choice                                      | value    | extension | encoding
		ServiceSpecificPermissionsChoices.opaque    | x        | false     | "80017b"
		ServiceSpecificPermissionsChoices.bitmapSsp | bitmapSsp| true      | "810403121314"
	}

	def "Verify toString"(){
		expect:
		new ServiceSpecificPermissions(ServiceSpecificPermissionsChoices.opaque, x).toString() == "ServiceSpecificPermissions [opaque=[7b]]"
		new ServiceSpecificPermissions(ServiceSpecificPermissionsChoices.bitmapSsp, bitmapSsp).toString() == "ServiceSpecificPermissions [bitmapSsp=[[121314]]]"
	}

}
