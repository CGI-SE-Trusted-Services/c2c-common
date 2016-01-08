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
package org.certificateservices.custom.c2x.ieee1609dot2.basic;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Date;

import net.time4j.Moment;
import net.time4j.TemporalType;
import net.time4j.scale.TimeScale;

/**
 * 
 * This data structure is a 64-bit integer giving an estimate of the number of (TAI) microseconds since
 * 00:00:00 UTC, 1 January, 2004.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Time64 extends Uint64 {
	
	private static final long serialVersionUID = 1L;
	
	private static final long SECONDSBETWEENTAIZEROAND2004 = 1009843232L;
	                                                          
	/**
	 * Constructor used when decoding
	 */
	public Time64(){
		super();
	}
	
	/**
	 * Main constructor for Time64
	 * 
	 * <b>Important: Note that this transformation is sometimes lossy: Leap seconds will get lost as well as micro- or nanoseconds.
	 * 
	 * @param timeStamp java date timestamp to convert
	 */
	public Time64(Date timeStamp) {
		super();
		Moment moment = TemporalType.JAVA_UTIL_DATE.translate(timeStamp);
		BigDecimal bd = moment.transform(TimeScale.TAI);
		this.value = bd.subtract(new BigDecimal(SECONDSBETWEENTAIZEROAND2004)).multiply(new BigDecimal(1000000)).toBigInteger();
		
	}
	
	/**
	 * Constructor used when encoding
	 * @param elapsedTime he number of (TAI) microseconds since 00:00:00 UTC, 1 January, 2004.
	 */
	public Time64(BigInteger elapsedTime){
		super(elapsedTime);
	}

	/** 
	 * Returns the timestamp as a Java util date.
	 * 
	 * <b>Important: Note that this transformation is sometimes lossy: Leap seconds will get lost as well as micro- or nanoseconds.
	 * @return the timestamp value
	 */
	public Date asDate(){
		long elapsedTime = this.value.divide(new BigInteger("1000000")).longValue();
		int nanoSeconds = this.value.remainder(new BigInteger("1000000")).intValue();
		Moment m = Moment.of(elapsedTime + SECONDSBETWEENTAIZEROAND2004,nanoSeconds, TimeScale.TAI);
		return TemporalType.JAVA_UTIL_DATE.from(m);
	}
	
	/**
	 * 
	 * @return the number of seconds since 1 Jan 2010 TAI
	 */
	public BigInteger asElapsedTime(){
		return getValue();
	}
	
	@Override
	public String toString() {
		return "Time64 [timeStamp=" + asDate() + " (" + getValue() + ")]";
	}
}
