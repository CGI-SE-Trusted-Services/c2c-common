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

import org.certificateservices.custom.c2x.common.Encodable;


/**
 * This structure defines how to encode time along with the standard deviation of time values. log_std_dev values
 * 0 to 253 represent the rounded up value of the log to the base 1,134666 of the implementation's estimate of the standard
 * deviation in units of nanoseconds. The value 254 represents any value greater than 1,134666 244 nanoseconds, i.e. a day
 * or longer. The value 255 indicates that the standard deviation is not known.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Time64WithStandardDeviation implements Encodable{
	
	private Time64 time;
	private int logStdDev;
	
	/**
	 * Main constructor for Time64WithStandardDeviation
	 * 
	 * 
	 * @param time a Time64 object
	 * @param logStdDev value 0 to 253 represent the rounded up value of the log to the base 1,134666 of the implementation's estimate of the standard
     *  deviation in units of nanoseconds. The value 254 represents any value greater than 1,134666 244 nanoseconds, i.e. a day
     *  or longer. The value 255 indicates that the standard deviation is not known.
	 */
	public Time64WithStandardDeviation(Time64 time, int logStdDev) {		
		this.time = time;
		this.logStdDev = logStdDev;
	}
		
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public Time64WithStandardDeviation(){
	
		
	}
	
	/**
	 * 
	 * @return the related Time64 object
	 */
	public Time64 getTime(){
		return time;
	}
	
	/**
	 * 
	 * @return value 0 to 253 represent the rounded up value of the log to the base 1,134666 of the implementation's estimate of the standard
     *  deviation in units of nanoseconds. The value 254 represents any value greater than 1,134666 244 nanoseconds, i.e. a day
     *  or longer. The value 255 indicates that the standard deviation is not known.
	 */
	public int getLogStdDev(){
		return logStdDev;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		time.encode(out);
		out.write(logStdDev);
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		time = new Time64();
		time.decode(in);
		logStdDev = in.read();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + logStdDev;
		result = prime * result + ((time == null) ? 0 : time.hashCode());
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
		Time64WithStandardDeviation other = (Time64WithStandardDeviation) obj;
		if (logStdDev != other.logStdDev)
			return false;
		if (time == null) {
			if (other.time != null)
				return false;
		} else if (!time.equals(other.time))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "Time64WithStandardDeviation [time=" + time.toString().replace("Time64 ", "") + ", logStdDev="
				+ logStdDev + "]";
	}
	
	/**
	 * Alternative toString version to get more verbose information
	 * @param certVersion the version of the certificate.
	 * @return a more verbose string version.
	 */
	public String toString(int certVersion) {
		return "Time64WithStandardDeviation [time=" + time.toString(certVersion).replace("Time64 ", "") + ", logStdDev="
				+ logStdDev + "]";
	}
	
	

	
}
