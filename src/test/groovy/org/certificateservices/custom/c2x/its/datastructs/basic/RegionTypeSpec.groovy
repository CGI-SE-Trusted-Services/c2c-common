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
package org.certificateservices.custom.c2x.its.datastructs.basic




import org.certificateservices.custom.c2x.its.datastructs.basic.RegionType;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.basic.RegionType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class RegionTypeSpec extends Specification{
	
	@Unroll
	def "Verify that #regionType has bytevalue #bytevalue"(){
		expect:
		regionType.byteValue instanceof Integer
		regionType.byteValue == bytevalue
		where:
		regionType        | bytevalue
		none              | 0
		circle            | 1
		rectangle         | 2
		polygon           | 3
		id                | 4

	}
	
	@Unroll
	def "Verify that RegionType.getByValue returns #regionType for #bytevalue"(){
		expect:
		RegionType.getByValue( bytevalue) == regionType
		where:
		regionType        | bytevalue
		none              | 0
		circle            | 1
		rectangle         | 2
		polygon           | 3
		id                | 4

	}

}
