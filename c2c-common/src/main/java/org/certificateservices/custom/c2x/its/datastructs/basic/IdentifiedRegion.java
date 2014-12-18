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
import java.nio.ByteBuffer;

import org.certificateservices.custom.c2x.its.datastructs.StructSerializer;


/**
 * This structure defines a predefined geographic region determined by the region dictionary region_dictionary and
 * the region identifier region_identifier. local_region may optionally specify a more detailed region within
 * the region. If the whole region is meant, local_region shall be set to 0.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class IdentifiedRegion implements StructSerializer{
	
	private RegionDictionary regionDictionary;
	private int regionIdentifier;
	private IntX localRegion;
	
	/**
	 * Main constructor for RectangularRegion
	 * 
	 * This structure defines a predefined geographic region determined by the region dictionary region_dictionary and
     * the region identifier region_identifier. local_region may optionally specify a more detailed region within
     * the region. If the whole region is meant, local_region shall be set to 0.
	 * 
	 * @param regionDictionary one of the region dictionary contants
	 * @param regionIdentifier identifier of the region.
	 * @param localRegion  local_region may optionally specify a more detailed region within
     * the region. If the whole region is meant, local_region shall be set to 0.
	 */
	public IdentifiedRegion(RegionDictionary regionDictionary,int regionIdentifier, IntX localRegion) {
		this.regionDictionary = regionDictionary;
		this.regionIdentifier = regionIdentifier;
		this.localRegion = localRegion;
	}

	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public IdentifiedRegion(){
	}

	/**
	 * 
	 * @return  one of the region dictionary contants
	 */
	public RegionDictionary getRegionDictionary(){
		return regionDictionary;
	}
	
	/**
	 * 
	 * @return  identifier of the region.
	 */
	public int getRegionIdentifier(){
		return regionIdentifier;
	}
	
	/**
	 * 
	 * @return  local_region may optionally specify a more detailed region within
     * the region. If the whole region is meant, local_region shall be set to 0.
	 */
	public IntX getLocalRegion(){
		return localRegion;
	}

	@Override
	public void serialize(DataOutputStream out) throws IOException {
		out.write(regionDictionary.getByteValue());
		out.write(ByteBuffer.allocate(4).putInt(regionIdentifier).array(),2,2);
		localRegion.serialize(out);
	}

	@Override
	public void deserialize(DataInputStream in) throws IOException {
		regionDictionary = RegionDictionary.getByValue(in.readByte());
		byte[] data = new byte[4];
		in.read(data,2,2);
		regionIdentifier = ByteBuffer.wrap(data).getInt();
		localRegion = new IntX();
		localRegion.deserialize(in);
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((localRegion == null) ? 0 : localRegion.hashCode());
		result = prime
				* result
				+ ((regionDictionary == null) ? 0 : regionDictionary.hashCode());
		result = prime * result + regionIdentifier;
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
		IdentifiedRegion other = (IdentifiedRegion) obj;
		if (localRegion == null) {
			if (other.localRegion != null)
				return false;
		} else if (!localRegion.equals(other.localRegion))
			return false;
		if (regionDictionary != other.regionDictionary)
			return false;
		if (regionIdentifier != other.regionIdentifier)
			return false;
		return true;
	}


	@Override
	public String toString() {
		return "IdentifiedRegion [regionDictionary=" + regionDictionary
				+ ", regionIdentifier=" + regionIdentifier + ", localRegion="
				+ localRegion + "]";
	}


}
