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

import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

/**
 * In this type:
 * 
 * <li>region -  identifies a region within a country as specified under CountryAndRegions.
 * <li>subregions - identifies one or more subregions as specified under CountryAndSubregions.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CountryAndSubregions extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int COUNTRY = 0;
	private static final int REGIONANDSUBREGIONS = 1;

	/**
	 * Constructor used when decoding
	 */
	public CountryAndSubregions(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public CountryAndSubregions(CountryOnly country, SequenceOfRegionAndSubregions regionAndSubregions){
		super(false,2);
		init();
		set(COUNTRY, country);
		set(REGIONANDSUBREGIONS, regionAndSubregions);
	}

	/**
	 * 
	 * @return Returns the country valye
	 */
	public CountryOnly getCountry(){
		return (CountryOnly) get(COUNTRY);
	}
	
	/**
	 * 
	 * @return Returns the sequence of regions and subregions
	 */
	public SequenceOfRegionAndSubregions getRegionAndSubregions(){
		return (SequenceOfRegionAndSubregions) get(REGIONANDSUBREGIONS);
	}
	
	private void init(){
		addField(COUNTRY, false, new CountryOnly(), null);
		addField(REGIONANDSUBREGIONS, false, new SequenceOfRegionAndSubregions(), null);
	}
	

	@Override
	public String toString() {
		COEREncodable[] sequenceValues = getRegionAndSubregions().getSequenceValues();
		String regions = "";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				regions += sequenceValues[i] + ",";
			}
			if(sequenceValues.length > 0){
				regions += sequenceValues[sequenceValues.length-1];
			}
		}
		
		return "CountryAndSubregions [country=" + getCountry().getValueAsLong() + ", region and subregions=" + regions+"]";
	}
	
}
