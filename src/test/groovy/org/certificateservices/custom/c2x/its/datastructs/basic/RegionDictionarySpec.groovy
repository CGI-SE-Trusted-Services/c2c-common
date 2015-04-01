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




import org.certificateservices.custom.c2x.its.datastructs.basic.RegionDictionary;

import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.basic.RegionDictionary.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class RegionDictionarySpec extends Specification{
	
	@Unroll
	def "Verify that #regionDictionary has bytevalue #bytevalue"(){
		expect:
		regionDictionary.byteValue instanceof Integer
		regionDictionary.byteValue == bytevalue
		where:
		regionDictionary    | bytevalue
		iso_3166_1          | 0
		un_stats            | 1


	}
	
	@Unroll
	def "Verify that RegionDictionary.getByValue returns #regionDictionary for #bytevalue"(){
		expect:
		RegionDictionary.getByValue( bytevalue) == regionDictionary
		where:
		regionDictionary    | bytevalue
		iso_3166_1          | 0
		un_stats            | 1

	}

}
