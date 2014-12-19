
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



import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class EccPointTypeSpec extends Specification{
	
	@Unroll
	def "Verify that #eccPointType has bytevalue #bytevalue"(){
		expect:
		eccPointType.byteValue instanceof Integer
		eccPointType.byteValue == bytevalue
		where:
		eccPointType                   | bytevalue
		x_coordinate_only              | 0
		compressed_lsb_y_0             | 2
		compressed_lsb_y_1             | 3
		uncompressed                   | 4

	}
	
	@Unroll
	def "Verify that EccPointType.getByValue returns #eccPointType for #bytevalue"(){
		expect:
		EccPointType.getByValue( bytevalue) == eccPointType
		where:
		eccPointType                   | bytevalue
		x_coordinate_only              | 0
		compressed_lsb_y_0             | 2
		compressed_lsb_y_1             | 3
		uncompressed                   | 4

	}

}
