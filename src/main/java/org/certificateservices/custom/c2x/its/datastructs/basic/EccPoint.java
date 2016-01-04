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
import java.math.BigInteger;
import java.util.Arrays;

import org.certificateservices.custom.c2x.common.EncodeHelper;
import org.certificateservices.custom.c2x.common.Encodable;

import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 * This structure defines a public key based on elliptic curve cryptography according to IEEE Std 1363-2000 [1]
 * clause 5.5.6. An EccPoint encodes a coordinate on a two dimensional elliptic curve. The x coordinate of this point
 * shall be encoded in x as an unsigned integer in network byte order. Depending on the key type, the y coordinate shall be
 * encoded case-specific:
 * <li> x_coordinate_only: only the x coordinate is encoded, no additional data shall be given.
 * <li> compressed_lsb_y_0: the point is compressed and y 's least significant bit is zero, no additional data 
 * shall be given.
 * <li> compressed_lsb_y_1: the point is compressed and y 's least significant bit is one, no additional data 
 * shall be given.
 * <li> uncompressed: the y coordinate is encoded in the field y. The y coordinate contained in a vector of length 
 * field_size containing opaque data shall be given.
 * <li> unknown: in all other cases, a variable-length vector containing opaque data shall be given.
 *
 * TODO determine why encoding of EccPointType is two octets
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EccPoint implements Encodable{
	
	private PublicKeyAlgorithm publicKeyAlgorithm;
	private BigInteger x;
	private byte[] compressedEncoding;
	private BigInteger y;
	private EccPointType eccPointType;
	
	/**
	 * Main constructor for EccPointType x_coordinate_only
	 * 
	 * @param publicKeyAlgorithm the related public key algorithm
	 * @param eccPointType the type eccPoint key
	 * @param x the x value of the public key.
	 */
	public EccPoint(PublicKeyAlgorithm publicKeyAlgorithm, EccPointType eccPointType, BigInteger x){
		this(publicKeyAlgorithm, eccPointType, x, null);
	}
	
	/**
	 * Main constructor for EccPointType compressed_lsb_y_0, compressed_lsb_y_1
	 * 
	 * @param publicKeyAlgorithm the related public key algorithm
	 * @param compressedEncoding encoded value of public key if size public key field size +1 where the first byte indicates the y bit value. Where
	 * '02' indicates y=0 and '03' y=1 
	 */
	public EccPoint(PublicKeyAlgorithm publicKeyAlgorithm, byte[] compressedEncoding) throws IllegalArgumentException{
		if(compressedEncoding.length != publicKeyAlgorithm.getFieldSize() +1){
			throw new IllegalArgumentException("Error in compressed encoding format, must be a byte array of size: public alg field size + 1");
		}
		this.publicKeyAlgorithm = publicKeyAlgorithm;
		if(compressedEncoding[0] == 02){
			eccPointType = compressed_lsb_y_0;
		}
		if(compressedEncoding[0] == 03){
			eccPointType = compressed_lsb_y_1;
		}
		this.compressedEncoding = compressedEncoding;
	} 
	
	/**
	 * Main constructor for EccPointType uncompressed
	 * 
	 * @param publicKeyAlgorithm the related public key algorithm
	 * @param eccPointType the type eccPoint key
	 * @param x the x value of the public key.
	 * @param y the y value of the public key.
	 */
	public EccPoint(PublicKeyAlgorithm publicKeyAlgorithm, EccPointType eccPointType, BigInteger x, BigInteger y){
		this.publicKeyAlgorithm = publicKeyAlgorithm;
		this.eccPointType = eccPointType;
		this.x = x;
		this.y = y;
	}
	

	
	/**
	 * Constructor used during serializing.
	 * 
	 * @param publicKeyAlgorithm the related public key algorithm
	 */
	public EccPoint(PublicKeyAlgorithm publicKeyAlgorithm){
		this.publicKeyAlgorithm = publicKeyAlgorithm;
	}
	
	/**
	 * 
	 * @return the related ecc point type
	 */
	public EccPointType getEccPointType(){
		return eccPointType;
	}
	
	/** 
	 * @return the x value of the public key,return null of EccPointType is of type compressed. 
	 */
	public BigInteger getX(){
		if(eccPointType != uncompressed && eccPointType != x_coordinate_only){
			return null;
		}
		return x;
	}
	
	/** 
	 * @return the y value of the public key, return null of EccPointType is not of type uncompressed.
	 */
	public BigInteger getY(){
		if(eccPointType != uncompressed){
			return null;
		}
		return y;
	}
	/** 
	 * @return the compressed encoding,return null of EccPointType is not of type compressed. 
	 */
	public byte[] getCompressedEncoding(){
		if(eccPointType != compressed_lsb_y_0 && eccPointType != compressed_lsb_y_1){
			return null;
		}
		return compressedEncoding;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(eccPointType.getByteValue());
		if(compressedEncoding != null){
			out.write(compressedEncoding, 1, publicKeyAlgorithm.getFieldSize());
		}
		if(x != null){
		  writeFixedFieldSizeKey(out,x);
		}
		if(y != null){
			writeFixedFieldSizeKey(out,y);
		}		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		eccPointType = EccPointType.getByValue(in.readByte());
		if(eccPointType == x_coordinate_only || eccPointType == uncompressed){
		  x = readFixedFieldSizeKey(in);
		}
		if(eccPointType == compressed_lsb_y_0 || eccPointType == compressed_lsb_y_1 ){
			compressedEncoding = new byte[publicKeyAlgorithm.getFieldSize() +1];
			in.read(compressedEncoding, 1, publicKeyAlgorithm.getFieldSize());
			if(eccPointType == compressed_lsb_y_0){
				compressedEncoding[0] = 0x2;
			}else{
				compressedEncoding[0] = 0x3;
			}
		}
		if(eccPointType == uncompressed){
			y = readFixedFieldSizeKey(in);
		}
	}

	private void writeFixedFieldSizeKey(DataOutputStream out, BigInteger keyValue) throws UnsupportedOperationException, IOException{
		EncodeHelper.writeFixedFieldSizeKey(publicKeyAlgorithm, out, keyValue);
	}
	
	private BigInteger readFixedFieldSizeKey(DataInputStream in) throws UnsupportedOperationException, IOException{
		return EncodeHelper.readFixedFieldSizeKey(publicKeyAlgorithm, in);
	}

	
	

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(compressedEncoding);
		result = prime * result
				+ ((eccPointType == null) ? 0 : eccPointType.hashCode());
		result = prime
				* result
				+ ((publicKeyAlgorithm == null) ? 0 : publicKeyAlgorithm
						.hashCode());
		result = prime * result + ((x == null) ? 0 : x.hashCode());
		result = prime * result + ((y == null) ? 0 : y.hashCode());
		return result;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		EccPoint other = (EccPoint) obj;
		if (!Arrays.equals(compressedEncoding, other.compressedEncoding))
			return false;
		if (eccPointType != other.eccPointType)
			return false;
		if (publicKeyAlgorithm != other.publicKeyAlgorithm)
			return false;
		if (x == null) {
			if (other.x != null)
				return false;
		} else if (!x.equals(other.x))
			return false;
		if (y == null) {
			if (other.y != null)
				return false;
		} else if (!y.equals(other.y))
			return false;
		return true;
	}

	@Override
	public String toString() {
		switch(eccPointType){
		case x_coordinate_only:
			return "EccPoint [publicKeyAlgorithm=" + publicKeyAlgorithm + ", x="
			+ x + ", eccPointType=" + eccPointType + "]";
		case compressed_lsb_y_0:
		case compressed_lsb_y_1:
				 return "EccPoint [publicKeyAlgorithm=" + publicKeyAlgorithm + ", compressedEncoding="
					+ Arrays.toString(compressedEncoding) + ", eccPointType=" + eccPointType + "]";
		case uncompressed:
			break;
		}
		return "EccPoint [publicKeyAlgorithm=" + publicKeyAlgorithm + ", x="
		+ x + ", y=" + y + ", eccPointType=" + eccPointType + "]";			
	}

	

}
