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
package org.certificateservices.custom.c2x.its.datastructs.msg



import org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.msg.PayloadType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class PayloadTypeSpec extends Specification{
	
	@Unroll
	def "Verify that #type has bytevalue #bytevalue"(){
		expect:
		type.byteValue instanceof Integer
		type.byteValue == bytevalue
		where:
		type                             | bytevalue
		unsecured                        | 0
		signed                           | 1
		encrypted                        | 2
		signed_external                  | 3
		signed_and_encrypted             | 4

	}
	
	@Unroll
	def "Verify that TrailerFieldType.getByValue returns #type for #bytevalue"(){
		expect:
		PayloadType.getByValue( bytevalue) == type
		where:
		type                             | bytevalue
		unsecured                        | 0
		signed                           | 1
		encrypted                        | 2
		signed_external                  | 3
		signed_and_encrypted             | 4

	}

}
