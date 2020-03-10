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

import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

import java.io.IOException;

/**
 * In this type:
 *
 * <ul>
 * <li>countryOnly - is a CountryOnly as defined in it's class.
 * <li>region - identifies one or more regions within the country. If countryOnly indicates the United States of America, 
 * the values in this field identify the state or statistically equivalent entity using the integer version of the 2010
 * FIPS codes as provided by the United States Census Bureau (see normative references in clause 2). For other values of
 * countryOnly, the meaning of region is not defined in this version of this standard.
 * </ul>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CountryAndRegions extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int COUNTRYONLY = 0;
	private static final int REGIONS = 1;

	/**
	 * Constructor used when decoding
	 */
	public CountryAndRegions(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public CountryAndRegions(CountryOnly countryOnly, SequenceOfUint8 regions) throws IOException {
		super(false,2);
		init();
		set(COUNTRYONLY, countryOnly);
		set(REGIONS, regions);
	}

	/**
	 * 
	 * @return Returns the countryOnly valye
	 */
	public CountryOnly getCountryOnly(){
		return (CountryOnly) get(COUNTRYONLY);
	}
	
	public SequenceOfUint8 getRegions(){
		return (SequenceOfUint8) get(REGIONS);
	}
	
	private void init(){
		addField(COUNTRYONLY, false, new CountryOnly(), null);
		addField(REGIONS, false, new SequenceOfUint8(), null);
	}
	

	@Override
	public String toString() {
		COEREncodable[] sequenceValues = getRegions().getSequenceValues();
		String regions = "";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				regions += ((Uint8) sequenceValues[i]).getValueAsLong() + ",";
			}
			if(sequenceValues.length > 0){
				regions += ((Uint8) sequenceValues[sequenceValues.length-1]).getValueAsLong();
			}
		}
		
		return "CountryAndRegions [countryOnly=" + getCountryOnly().getValueAsLong() + ", regions=" + regions+"]";
	}
	
}
