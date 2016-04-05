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
package org.certificateservices.custom.c2x.its.datastructs.basic;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.util.Date;

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;

import net.time4j.Moment;
import net.time4j.TemporalType;
import net.time4j.scale.TimeScale;


/**
 * For Version 2 certificates:
 * <p>
 * Time32 is an unsigned 32-bit integer, encoded in big-endian format, giving the number of International Atomic Time
 * (TAI) seconds since 00:00:00 UTC, 01 January 2004. 
 * <p>
 * For Version 1 certificates:
 * <p>
 * Time32 is an unsigned 32-bit integer, encoded in big-endian format, giving the number of International Atomic Time
 * (TAI) seconds since 00:00:00 UTC, 1 January, 2010.
 * <p>
 * NOTE 1: The period of 2 32 seconds lasts about 136 years, that is until 2146. 
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Time32 implements Encodable{
	
	private static final long SECONDSBETWEENTAIZEROAND2004 = 1009843232L;
	private static final long SECONDSBETWEENTAIZEROAND2010 = 1199232034L;
	
	private long timeStamp;
	
	/**
	 * Main constructor for Time32
	 * 
	 * <b>Important: Note that this transformation is sometimes lossy: Leap seconds will get lost as well as micro- or nanoseconds.
	 * 
	 * @param certVersion version of certificate
	 * @param timeStamp   java date timestamp to convert
	 */
	public Time32(int certVersion, Date timeStamp) {		
		Moment moment = TemporalType.JAVA_UTIL_DATE.translate(timeStamp);
		BigDecimal bd = moment.transform(TimeScale.TAI);
		if(certVersion == Certificate.CERTIFICATE_VERSION_1){
		  this.timeStamp = bd.subtract(new BigDecimal(SECONDSBETWEENTAIZEROAND2010)).longValue();
		}else{
			this.timeStamp = bd.subtract(new BigDecimal(SECONDSBETWEENTAIZEROAND2004)).longValue();
		}
	}
	
	/**
	 * Main constructor for Time32
	 * 
	 * @param elapsedTime  the number of seconds since 1 Jan 2010 TAI
	 */
	public Time32(long elapsedTime) {		
		this.timeStamp =elapsedTime;
	}
	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public Time32(){
	
		
	}
	
	/** 
	 * Returns the timestamp as a Java util date.
	 * 
	 * @param certVersion indicating with certificate version to parse the value as, since the different
	 * versions have different base times.
	 * 
	 * <b>Important: Note that this transformation is sometimes lossy: Leap seconds will get lost as well as micro- or nanoseconds.
	 * @return the timestamp value
	 */
	public Date asDate(int certVersion){
		Moment m; 
		if(certVersion == Certificate.CERTIFICATE_VERSION_1){
			m = Moment.of(this.timeStamp + SECONDSBETWEENTAIZEROAND2010, TimeScale.TAI);
		}else{
			m = Moment.of(this.timeStamp + SECONDSBETWEENTAIZEROAND2004, TimeScale.TAI);
		}
		return TemporalType.JAVA_UTIL_DATE.from(m);
	}
	
	/**
	 * 
	 * @return the number of seconds since 1 Jan 2010 TAI
	 */
	public long asElapsedTime(){
		return timeStamp;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(ByteBuffer.allocate(8).putLong(timeStamp).array(),4,4);		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		byte[] data = new byte[8];
		in.read(data,4,4);
		timeStamp = ByteBuffer.wrap(data).getLong();
	}

	@Override
	public String toString() {
		return "Time32 [" +timeStamp + "]";
	}
	
	/**
	 * Alternative toString version to get more verbose information
	 * @param certVersion the version of the certificate.
	 * @return a more verbose string version.
	 */
	public String toString(int certVersion) {
		return "Time32 [" + asDate(certVersion) + " (" + timeStamp + ")]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (timeStamp ^ (timeStamp >>> 32));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Time32 other = (Time32) obj;
		if (timeStamp != other.timeStamp)
			return false;
		return true;
	}

	
}
