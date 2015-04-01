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
package org.certificateservices.custom.c2x.its.datastructs.cert



import org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestrictionType;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestrictionType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class ValidityRestrictionTypeSpec extends Specification{
	
	@Unroll
	def "Verify that #validityRestrictionType has bytevalue #bytevalue"(){
		expect:
		validityRestrictionType.byteValue instanceof Integer
		validityRestrictionType.byteValue == bytevalue
		where:
		validityRestrictionType  | bytevalue
		time_end                 | 0
		time_start_and_end       | 1
		time_start_and_duration  | 2
		region                   | 3
	}
	
	@Unroll
	def "Verify that ValidityRestrictionType.getByValue returns #validityRestrictionType for #bytevalue"(){
		expect:
		ValidityRestrictionType.getByValue(bytevalue) == validityRestrictionType
		where:
		validityRestrictionType  | bytevalue
		time_end                 | 0
		time_start_and_end       | 1
		time_start_and_duration  | 2
		region                   | 3

	}

}
