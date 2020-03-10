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

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;

/**
 * This type represents the duration of validity of a certificate. The Uint16 value is the duration, given in the
 * units denoted by the indicated choice. A year is considered to be 31556952 seconds, which is the average
 * number of seconds in a year; if it is desired to map years more closely to wall-clock days, this can be done
 * using the hours choice for up to seven years and the sixtyHours choice for up to 448.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Duration extends COERChoice {
	
	private static final long serialVersionUID = 1L;
	
	public enum DurationChoices implements COERChoiceEnumeration{
		microseconds,
		milliseconds,
		seconds,
		minutes,
		hours,
		sixtyHours,
		years;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			return new Uint16();
		}

		/**
		 * @return always false, no extension exists.
		 */
		@Override
		public boolean isExtension() {
			return false;
		}
	}
	
	/**
	 * Constructor used when encoding.
	 */
	public Duration(DurationChoices choice, int value) throws IOException {
		super(choice, new Uint16(value));
	}

	/**
	 * Constructor used when decoding.
	 */
	public Duration() {
		super(DurationChoices.class);
	}
	
	/**
	 * 
	 * @return the duration value as an integer.
	 */
	public int getValueAsInt(){
		return (int) ((Uint16) value).getValueAsLong();
	}
	
	/**
	 * Returns the duration unit.
	 */
	public DurationChoices getUnit(){
		return (DurationChoices) choice;
	}

	@Override
	public String toString() {
		return "Duration [" + ((Uint16) value).getValueAsLong() + " " + choice +"]";
	}
	
}
