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
import java.util.List;

import org.certificateservices.custom.c2x.common.EncodeHelper;
import org.certificateservices.custom.c2x.common.Encodable;


/**
 * This structure defines how to encode geographic regions. These regions can be used to limit the validity of certificates.
 * In case of rectangle, the region shall consist of a variable-length vector of rectangles that may be overlapping or
 * disjoint. The variable-length vector shall not contain more than 6 rectangles. The region covered by the rectangles shall
 * be continuous and shall not contain holes.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class GeographicRegion implements Encodable{
	
	static final int MAX_RECTANGULAR_REGIONS = 6;
	
	private RegionType regionType;
	private CircularRegion circularRegion;
	private List<RectangularRegion> rectangularRegions;
	private PolygonalRegion polygonalRegion;
	private IdentifiedRegion identifiedRegion;
	

	/**
	 * Constructor used during serializing or region type: none
	 * 
	 */
	public GeographicRegion(){
		regionType = RegionType.none;
	}
	
	/**
	 * Constructor for a geographic region defined by a circular region.
	 * 
	 */
	public GeographicRegion(CircularRegion circularRegion) {
		this.regionType = RegionType.circle;
		this.circularRegion = circularRegion;
	}
	
	/**
	 * Constructor for a geographic region defined by a rectangular region.
	 * 
	 */
	public GeographicRegion(List<RectangularRegion> rectangularRegions) throws IllegalArgumentException {
		if(rectangularRegions.size() > MAX_RECTANGULAR_REGIONS){
			throw new IllegalArgumentException("Invalid number of rectangular regions ( " + rectangularRegions.size() + " ), a maximum of " + MAX_RECTANGULAR_REGIONS + " is supported.");
		}
		this.regionType = RegionType.rectangle;
		this.rectangularRegions = rectangularRegions;
	}
	
	/**
	 * Constructor for a geographic region defined by a polygonal region.
	 * 
	 */
	public GeographicRegion(PolygonalRegion polygonalRegion) throws IllegalArgumentException {
		this.regionType = RegionType.polygon;
		this.polygonalRegion = polygonalRegion;
	}
	
	/**
	 * Constructor for a geographic region defined by a identified region.
	 * 
	 */
	public GeographicRegion(IdentifiedRegion identifiedRegion) throws IllegalArgumentException {
		this.regionType = RegionType.id;
		this.identifiedRegion = identifiedRegion;
	}

	



	/**
	 * 
	 * @return the type of geographic region.
	 */
	public RegionType getRegionType() {
		return regionType;
	}

	/**
	 * 
	 * @return returns the circular region if region type is circular, otherwise null.
	 */
	public CircularRegion getCircularRegion() {
		return circularRegion;
	}

	/**
	 * 
	 * @return returns a list of rectangular regions if region type is rectangular, otherwise null.
	 */
	public List<RectangularRegion> getRectangularRegions() {
		return rectangularRegions;
	}

	/**
	 * 
	 * @return returns the polygonal region if region type is polygon, otherwise null.
	 */
	public PolygonalRegion getPolygonalRegion() {
		return polygonalRegion;
	}

	/**
	 * 
	 * @return returns the identified region if region type is id, otherwise null.
	 */
	public IdentifiedRegion getIdentifiedRegion() {
		return identifiedRegion;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(regionType.getByteValue());
		switch (regionType) {
		case none:
			break;
		case circle:
			circularRegion.encode(out);
			break;
        case rectangle:
    		EncodeHelper.encodeVariableSizeVector(out, rectangularRegions);
			break;
        case polygon:
        	polygonalRegion.encode(out);
			break;
        case id:
        	identifiedRegion.encode(out);
			break;
		default:
			break;
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void decode(DataInputStream in) throws IOException {
		regionType = RegionType.getByValue(in.readByte());
		switch (regionType) {
		case none:
			break;
		case circle:
			circularRegion = new CircularRegion();
			circularRegion.decode(in);
			break;
        case rectangle:
    		rectangularRegions = (List<RectangularRegion>) EncodeHelper.decodeVariableSizeVector(in, RectangularRegion.class);
			break;
        case polygon:
        	polygonalRegion = new PolygonalRegion();
        	polygonalRegion.decode(in);
			break;
        case id:
        	identifiedRegion = new IdentifiedRegion();
        	identifiedRegion.decode(in);
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
				+ ((circularRegion == null) ? 0 : circularRegion.hashCode());
		result = prime
				* result
				+ ((identifiedRegion == null) ? 0 : identifiedRegion.hashCode());
		result = prime * result
				+ ((polygonalRegion == null) ? 0 : polygonalRegion.hashCode());
		result = prime
				* result
				+ ((rectangularRegions == null) ? 0 : rectangularRegions
						.hashCode());
		result = prime * result
				+ ((regionType == null) ? 0 : regionType.hashCode());
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
		GeographicRegion other = (GeographicRegion) obj;
		if (circularRegion == null) {
			if (other.circularRegion != null)
				return false;
		} else if (!circularRegion.equals(other.circularRegion))
			return false;
		if (identifiedRegion == null) {
			if (other.identifiedRegion != null)
				return false;
		} else if (!identifiedRegion.equals(other.identifiedRegion))
			return false;
		if (polygonalRegion == null) {
			if (other.polygonalRegion != null)
				return false;
		} else if (!polygonalRegion.equals(other.polygonalRegion))
			return false;
		if (rectangularRegions == null) {
			if (other.rectangularRegions != null)
				return false;
		} else if (!rectangularRegions.equals(other.rectangularRegions))
			return false;
		if (regionType != other.regionType)
			return false;
		return true;
	}

	@Override
	public String toString() {
		switch (regionType) {
		case circle:
			return "GeographicRegion [regionType=" + regionType
					+ ", circularRegion=" + circularRegion.toString().replace("CircularRegion ", "") + "]";
        case rectangle:
    		String recString = "";
    		for(int i=0; i < rectangularRegions.size() -1; i++){
    			recString += rectangularRegions.get(i).toString().replace("RectangularRegion ","") + ", ";
    		}
    		if(rectangularRegions.size() > 0){
    			recString += rectangularRegions.get(rectangularRegions.size()-1).toString().replace("RectangularRegion ","");
    		}
			return "GeographicRegion [regionType=" + regionType
					+ ", rectangularRegions=" + recString + "]";
        case polygon:
			return "GeographicRegion [regionType=" + regionType
					+ ", polygonalRegion=" + polygonalRegion.toString().replace("PolygonalRegion ", "") + "]";
        case id:
			return "GeographicRegion [regionType=" + regionType
					+ ", identifiedRegion=" + identifiedRegion.toString().replace("IdentifiedRegion ", "") + "]";
		default:
			break;
		}
		return "GeographicRegion [regionType=" + regionType + "]";
	}



}
