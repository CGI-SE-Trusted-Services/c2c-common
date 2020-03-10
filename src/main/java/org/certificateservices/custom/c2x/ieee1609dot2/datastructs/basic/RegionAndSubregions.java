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
 * <li>region - identifies a region within a country as specified under CountryAndRegions.</li>
 * <li>subregions - identifies one or more subregions as specified under CountryAndSubregions.</li>
 * </ul>
 * <p>
 *     <b>Critical information fields:</b>RegionAndSubregions is a critical information field as defined in 5.2.5. An
 * implementation that does not detect or recognize the the region or subregions values when verifying a
 * signed SPDU shall indicate that the signed SPDU is invalid.
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class RegionAndSubregions extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int REGION = 0;
	private static final int SUBREGIONS = 1;

	/**
	 * Constructor used when decoding
	 */
	public RegionAndSubregions(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public RegionAndSubregions(int region, SequenceOfUint16 subregions) throws IOException {
		super(false,2);
		init();
		set(REGION, new Uint8(region));
		set(SUBREGIONS, subregions);
	}

	/**
	 * 
	 * @return Returns the region
	 */
	public int getRegion(){
		return (int) ((Uint8) get(REGION)).getValueAsLong();
	}
	
	public SequenceOfUint16 getSubRegions(){
		return (SequenceOfUint16) get(SUBREGIONS);
	}
	
	private void init(){
		addField(REGION, false, new Uint8(), null);
		addField(SUBREGIONS, false, new SequenceOfUint16(), null);
	}
	

	@Override
	public String toString() {
		COEREncodable[] sequenceValues = getSubRegions().getSequenceValues();
		String subRegions = "";
		if(sequenceValues != null){
			for(int i=0; i< sequenceValues.length -1;i++){
				subRegions += ((Uint16) sequenceValues[i]).getValueAsLong() + ",";
			}
			if(sequenceValues.length > 0){
				subRegions += ((Uint16) sequenceValues[sequenceValues.length-1]).getValueAsLong();
			}
		}
		
		
		return "RegionAndSubregions [region=" + getRegion() + ", subregions=" + subRegions+"]";
	}
	
}
