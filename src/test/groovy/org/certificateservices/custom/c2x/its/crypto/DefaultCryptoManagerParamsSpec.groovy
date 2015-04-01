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
package org.certificateservices.custom.c2x.its.crypto

import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;

/**
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class DefaultCryptoManagerParamsSpec extends Specification {

	def "Verify that constructor and getters and setters work"(){
		expect:
		new DefaultCryptoManagerParams("BC").getProvider() == "BC"
	}
}
