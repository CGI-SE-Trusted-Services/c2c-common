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
package org.certificateservices.custom.c2x.its.datastructs.cert;

import static org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestrictionType.time_end;
import static org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestrictionType.time_start_and_duration;
import static org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestrictionType.time_start_and_end;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.its.datastructs.basic.Duration;
import org.certificateservices.custom.c2x.its.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32;

/**
 * This structure defines how to encode geographic regions. These regions can be used to limit the validity of certificates.
 * In case of rectangle, the region shall consist of a variable-length vector of rectangles that may be overlapping or
 * disjoint. The variable-length vector shall not contain more than 6 rectangles. The region covered by the rectangles shall
 * be continuous and shall not contain holes.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ValidityRestriction implements Encodable{
	
	static final int MAX_RECTANGULAR_REGIONS = 6;
	
	private ValidityRestrictionType validityRestrictionType;
	private Time32 startValidity;
	private Time32 endValidity;
	private Duration duration;
	private GeographicRegion region;
	

	/**
	 * Constructor used for validity restriction of type time_end
	 * 
	 */
	public ValidityRestriction(Time32 end_validity){
		this.validityRestrictionType = time_end;
		this.endValidity = end_validity;
	}
	
	/**
	 * Constructor used for validity restriction of type time_start_and_end
	 * 
	 */
	public ValidityRestriction(Time32 start_validity, Time32 end_validity) {
		this.validityRestrictionType = time_start_and_end;
		this.startValidity = start_validity;
		this.endValidity = end_validity;
	}
	
	/**
	 * Constructor used for validity restriction of type time_start_and_duration
	 * 
	 */
	public ValidityRestriction(Time32 start_validity, Duration duration) {
		this.validityRestrictionType = time_start_and_duration;
		this.startValidity = start_validity;
		this.duration = duration;
	}
	
	/**
	 * Constructor used for validity restriction of type region
	 * 
	 */
	public ValidityRestriction(GeographicRegion region) {
		this.validityRestrictionType = ValidityRestrictionType.region;
		this.region = region;
	}

	/**
	 * Constructor used during serializing
	 * 
	 */
	public ValidityRestriction(){
	}

	/**
	 * 
	 * @return the type of validity restriction.
	 */
	public ValidityRestrictionType getValidityRestrictionType() {
		return validityRestrictionType;
	}

	/**
	 * 
	 * @return returns the start validity if type is time_start_and_end or time_start_and_duration, otherwise null.
	 */
	public Time32 getStartValidity() {
		return startValidity;
	}

	/**
	 * 
	 * @return returns the end validity if type is time_start_and_end or time_end, otherwise null.
	 */
	public Time32 getEndValidity() {
		return endValidity;
	}

	/**
	 * 
	 * @return returns the duration if type is time_start_and_duration, otherwise null.
	 */
	public Duration getDuration() {
		return duration;
	}

	/**
	 * 
	 * @return returns the geographic region if type is region, otherwise null.
	 */
	public GeographicRegion getIdentifiedRegion() {
		return region;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(validityRestrictionType.getByteValue());
		switch (validityRestrictionType) {
		case time_end:
			endValidity.encode(out);
			break;
        case time_start_and_end:
        	startValidity.encode(out);
			endValidity.encode(out);
			break;
        case time_start_and_duration:
        	startValidity.encode(out);
			duration.encode(out);
			break;
        case region:
        	region.encode(out);
			break;
		default:
			break;
		}
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		validityRestrictionType = ValidityRestrictionType.getByValue(in.readByte());
		switch (validityRestrictionType) {
		case time_end:
			endValidity = new Time32();
			endValidity.decode(in);
			break;
        case time_start_and_end:
        	startValidity = new Time32();
        	startValidity.decode(in);
			endValidity = new Time32();
			endValidity.decode(in);
			break;
        case time_start_and_duration:
        	startValidity = new Time32();
        	startValidity.decode(in);
        	duration = new Duration();
        	duration.decode(in);
			break;
        case region:
        	region = new GeographicRegion();
        	region.decode(in);
			break;
		default:
			break;
		}
	}



	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((duration == null) ? 0 : duration.hashCode());
		result = prime * result
				+ ((endValidity == null) ? 0 : endValidity.hashCode());
		result = prime * result + ((region == null) ? 0 : region.hashCode());
		result = prime * result
				+ ((startValidity == null) ? 0 : startValidity.hashCode());
		result = prime
				* result
				+ ((validityRestrictionType == null) ? 0
						: validityRestrictionType.hashCode());
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
		ValidityRestriction other = (ValidityRestriction) obj;
		if (duration == null) {
			if (other.duration != null)
				return false;
		} else if (!duration.equals(other.duration))
			return false;
		if (endValidity == null) {
			if (other.endValidity != null)
				return false;
		} else if (!endValidity.equals(other.endValidity))
			return false;
		if (region == null) {
			if (other.region != null)
				return false;
		} else if (!region.equals(other.region))
			return false;
		if (startValidity == null) {
			if (other.startValidity != null)
				return false;
		} else if (!startValidity.equals(other.startValidity))
			return false;
		if (validityRestrictionType != other.validityRestrictionType)
			return false;
		return true;
	}

	@Override
	public String toString() {
		switch (validityRestrictionType) {
		case time_end:
			return "ValidityRestriction [type=" + validityRestrictionType
					+ ", end_validity=" + endValidity + "]";
        case time_start_and_end:
			return "ValidityRestriction [type=" + validityRestrictionType +", start_validity=" + startValidity 
					 +", end_validity=" + endValidity + "]";
        case time_start_and_duration:
			return  "ValidityRestriction [type=" + validityRestrictionType +", start_validity=" + startValidity 
					 +", duration=" + duration + "]";
        case region:
			return "ValidityRestriction [type=" + validityRestrictionType
					+ ", region:=" + region + "]";
		default:
			break;
		}
		return "ValidityRestriction [type=unknown]";
	}



}
