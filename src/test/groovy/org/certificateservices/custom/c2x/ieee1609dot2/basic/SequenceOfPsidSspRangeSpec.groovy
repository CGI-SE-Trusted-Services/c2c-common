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
package org.certificateservices.custom.c2x.ieee1609dot2.basic

import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream
import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IdentifiedRegion.IdentifiedRegionChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SspRange.SspRangeChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all SequenceOfPsidSspRange class
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfPsidSspRangeSpec extends BaseStructSpec {

	Psid id1 = new Psid(101)
	Psid id2 = new Psid(64321)
	
	SequenceOfOctetString soc = new SequenceOfOctetString([new COEROctetStream("test1".getBytes()),new COEROctetStream("test2".getBytes())])
	SspRange ssprange1 = new SspRange(SspRangeChoices.all, null)
	SspRange ssprange2 = new SspRange(SspRangeChoices.opaque, soc)
	
	PsidSspRange psr1 = new PsidSspRange(id1,ssprange1)
	PsidSspRange psr2 = new PsidSspRange(id2,ssprange2)
	
	
	def "Verify that SequenceOfPsidSspRange is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfPsidSspRange(),"0102400165814002fb41800102057465737431057465737432")
		then:
		u1.getSequenceValues()[0] == psr1
		u1.getSequenceValues()[1] == psr2
		when:
		def u2 = new SequenceOfPsidSspRange([psr1,psr2] as PsidSspRange[])
		then:
		u2.getSequenceValues()[0] == psr1
		u2.getSequenceValues()[1] == psr2
		
		
		when:
		def u3 = new SequenceOfPsidSspRange([psr1,psr2])
		then:
		u3.getSequenceValues()[0] == psr1
		u3.getSequenceValues()[1] == psr2
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfPsidSspRange([psr1,psr2]).toString() == "SequenceOfPsidSspRange [[psid=[101(65)], sspRange=[all]],[psid=[64321(fb41)], sspRange=[opaque=[[COEROctetStream [data=7465737431],COEROctetStream [data=7465737432]]]]]]"
		new SequenceOfPsidSspRange().toString() == "SequenceOfPsidSspRange []"
		new SequenceOfPsidSspRange([psr1]).toString() == "SequenceOfPsidSspRange [[psid=[101(65)], sspRange=[all]]]"
		
	
	}
	
	


}
