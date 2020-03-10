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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Date;

import net.time4j.Moment;
import net.time4j.TemporalType;
import net.time4j.scale.TimeScale;

/**
 * This type gives the number of (TAI) seconds since 00:00:00 UTC, 1 January, 2004.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Time32 extends Uint32 {
	
	private static final long serialVersionUID = 1L;
	
	private static final long SECONDSBETWEENTAIZEROAND2004 = 1009843232L;
	                                                          
	/**
	 * Constructor used when decoding
	 */
	public Time32(){
		super();
	}
	
	/**
	 * Main constructor for Time32
	 * 
	 * <b>Important: Note that this transformation is sometimes lossy: Leap seconds will get lost as well as micro- or nanoseconds.
	 * 
	 * @param timeStamp   java date timestamp to convert
	 */
	public Time32(Date timeStamp) {
		super();
		Moment moment = TemporalType.JAVA_UTIL_DATE.translate(timeStamp);
		BigDecimal bd = moment.transform(TimeScale.TAI);
		value = bd.subtract(new BigDecimal(SECONDSBETWEENTAIZEROAND2004)).toBigInteger();
		
	}
	
	/**
	 * Constructor used when encoding
	 */
	public Time32(long elapsedTime) throws IOException {
		super(elapsedTime);
	}

	/** 
	 * Returns the timestamp as a Java util date.
	 * 
	 * <b>Important: Note that this transformation is sometimes lossy: Leap seconds will get lost as well as micro- or nanoseconds.
	 * @return the timestamp value
	 */
	public Date asDate(){

		Moment m = Moment.of(this.getValueAsLong() + SECONDSBETWEENTAIZEROAND2004, TimeScale.TAI);
		return TemporalType.JAVA_UTIL_DATE.from(m);
	}
	
	/**
	 * 
	 * @return the number of seconds since 1 Jan 2010 TAI
	 */
	public long asElapsedTime(){
		return getValueAsLong();
	}
	
	@Override
	public String toString() {
		return "Time32 [timeStamp=" + asDate() + " (" + getValueAsLong() + ")]";
	}
}
