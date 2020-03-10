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
import java.util.Date;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;

/**
 * This type gives the validity period of a certificate. The start of the validity period is given by start and
 * the end is given by start + duration.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ValidityPeriod extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int START = 0;
	private static final int DURATION = 1;

	/**
	 * Constructor used when decoding
	 */
	public ValidityPeriod(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public ValidityPeriod(Time32 start, Duration duration) throws IOException {
		super(false,2);
		init();
		set(START, start);
		set(DURATION, duration);
	}

	/**
	 * Simplified constructor
	 */
	public ValidityPeriod(Date start, DurationChoices durationType, int duration) throws IOException {
		this(new Time32(start), new Duration(durationType, duration));
	}
	
	/**
	 * 
	 * @return the validity period start
	 */
	public Time32 getStart(){
		return (Time32) get(START);
	}
	
	/**
	 * 
	 * @return the validity period duration
	 */
	public Duration getDuration(){
		return (Duration) get(DURATION);
	}
	
	private void init(){
		addField(START, false, new Time32(), null);
		addField(DURATION, false, new Duration(), null);
	}
	

	@Override
	public String toString() {
		return "ValidityPeriod [start=" + getStart() + ", duration=" + getDuration()+"]";
	}
	
}
