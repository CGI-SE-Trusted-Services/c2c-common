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



import org.certificateservices.custom.c2x.its.datastructs.msg.TrailerFieldType;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.msg.TrailerFieldType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class TrailerFieldTypeSpec extends Specification{
	
	@Unroll
	def "Verify that #type has bytevalue #bytevalue"(){
		expect:
		type.byteValue instanceof Integer
		type.byteValue == bytevalue
		where:
		type                           | bytevalue
		signature                      | 1

	}
	
	@Unroll
	def "Verify that TrailerFieldType.getByValue returns #type for #bytevalue"(){
		expect:
		TrailerFieldType.getByValue( bytevalue) == type
		where:
		type                           | bytevalue
		signature                      | 1

	}

}
