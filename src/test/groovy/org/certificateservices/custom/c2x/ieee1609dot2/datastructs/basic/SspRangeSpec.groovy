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
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfOctetString
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange

import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SspRange.SspRangeChoices.*

/**
 * Test for SspRange
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SspRangeSpec extends BaseStructSpec {
	
	SequenceOfOctetString soc = new SequenceOfOctetString([new COEROctetStream("test1".getBytes()),new COEROctetStream("test2".getBytes())])
	BitmapSspRange bsr = new BitmapSspRange( Hex.decode("010203040506070809"),Hex.decode("111203040506071819"))
	

	def "Verify that SspRange is correctly encoded for type all"(){
		when:
		def sr = new SspRange(all)
		
		then:
		serializeToHex(sr) == "81"

		when:
		sr = new SspRange(all, null)

		then:
		serializeToHex(sr) == "81"
		
		when:
		SspRange sr2 = deserializeFromHex(new SspRange(), "81")
		
		then:
		sr2.getOpaqueData() == null
		sr2.getBitmapSspRange() == null
		sr2.choice == all
		sr2.type == all
		!sr2.choice.extension
	}

	def "Verify that SspRange is correctly encoded for type opaque"(){
		when:
		def sr = new SspRange(opaque, soc)

		then:
		serializeToHex(sr) == "800102057465737431057465737432"

		when:
		SspRange sr2 = deserializeFromHex(new SspRange(), "800102057465737431057465737432")

		then:
		sr2.getOpaqueData() == soc
		sr2.getBitmapSspRange() == null
		sr2.choice == opaque
		sr2.type == opaque
		!sr2.choice.extension
	}

	def "Verify that SspRange is correctly encoded for type bitmapSspRange"(){
		when:
		def sr = new SspRange(bitmapSspRange, bsr)

		then:
		serializeToHex(sr) == "82140901020304050607080909111203040506071819"

		when:
		SspRange sr2 = deserializeFromHex(new SspRange(), "82140901020304050607080909111203040506071819")

		then:
		sr2.getOpaqueData() == null
		sr2.getBitmapSspRange() == bsr
		sr2.choice == bitmapSspRange
		sr2.type == bitmapSspRange
		sr2.choice.extension
	}

	def "Verify that IllegalArgumentException is thrown for invalid constructor data"(){
		when:
		new SspRange(all, bsr)
		then:
		def e = thrown IllegalArgumentException
		e.message == "Invalid SspRange, if choice is all must related data be null."
		when:
		new SspRange(opaque, bsr)
		then:
		e = thrown IllegalArgumentException
		e.message == "Invalid SspRange, if choice is opaque must related data be of type SequenceOfOctetString."
		when:
		new SspRange(bitmapSspRange, soc)
		then:
		e = thrown IllegalArgumentException
		e.message == "Invalid SspRange, if choice is bitmapSspRange must related data be of type BitmapSspRange."
	}

	def "Verify toString"(){
		expect:
		new SspRange(opaque, soc).toString() == "SspRange [opaque=[[COEROctetStream [data=7465737431],COEROctetStream [data=7465737432]]]]"
		new SspRange(bitmapSspRange, bsr).toString() == "SspRange [bitmapSspRange=[[sspValue=010203040506070809, sspBitmask=111203040506071819]]]"
		new SspRange(all, null).toString() == "SspRange [all]"
	}

}
