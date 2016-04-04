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

import static org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType.assurance_level;
import static org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType.encryption_key;
import static org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType.its_aid_list;
import static org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType.its_aid_ssp_list;
import static org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType.priority_its_aid_list;
import static org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType.priority_ssp_list;
import static org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType.reconstruction_value;
import static org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType.verification_key;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.List;

import org.certificateservices.custom.c2x.common.EncodeHelper;
import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey;

/**
 * This structure defines how to encode a subject attribute. These attributes serve the purpose of specifying the technical
 * details of a certificate's subject. Depending on the value of type, the following additional data shall be given:
 * 
 * <li> verification_key and encryption_key: a public key contained in a PublicKey structure shall be
 * given.
 * <li> reconstruction_value: an ECC point contained in a EccPoint structure shall be given.
 * <li> assurance_level: the assurance level for the subject contained in a SubjectAssurance structure
 * shall be given.
 * <li> its_aid_list: ITS-AIDs contained in a variable-length vector of type IntX shall be given.
 * <li> Its_aid_ssp_list: ITS-AIDs with associated SSPs contained in a variable-length vector of type
 * ItsAidSsp shall be given.
 * <li> priority_its_aid_list: ITS-AIDs and associated maximum priorities contained in a variable-length
 * vector of type ItsAidPriority shall be given.
 * <li> priority_ssp_list: ITS-AIDs and associated SSPs and m
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SubjectAttribute implements Encodable{
	
	
	private SubjectAttributeType subjectAttributeType;
	private PublicKey key;
	private EccPoint rv;
	private SubjectAssurance assuranceLevel;
	private List<Encodable> itsAidList;
	

	/**
	 * Constructor used to create a SubjectAttribute of types verification_key and encryption_key
	 * 
	 */
	public SubjectAttribute(SubjectAttributeType subjectAttributeType, PublicKey key){
		if(subjectAttributeType != verification_key && subjectAttributeType != encryption_key){
			throw new IllegalArgumentException("Illegal subject attribute type, public key is only supported by types " + verification_key + " and " + encryption_key);
		}
		this.subjectAttributeType = subjectAttributeType;
		this.key = key;
	}
	
	/**
	 * Constructor used to create a SubjectAttribute of type reconstruction_value
	 * 
	 */
	public SubjectAttribute(EccPoint rv){
		this.subjectAttributeType = reconstruction_value;
		this.rv = rv;
		// TODO, public key algorithm deserialization not defined.
		throw new IllegalArgumentException("Error reconstruction value is currently not supported.");
	}
	
	/**
	 * Constructor used for SubjectAttribute of type assurance_level
	 * 
	 */
	public SubjectAttribute(SubjectAssurance assuranceLevel) {
		this.subjectAttributeType = assurance_level;
		this.assuranceLevel = assuranceLevel;
	}
	
	/**
	 * Constructor used for SubjectAttribute of types its_aid_list,its_aid_ssp_list,priority_its_aid_list,priority_ssp_list.
	 * 
	 * The itsAidList should contain object of the following types depending on type:
	 * <p>
	 * <li>its_aid_list : IntX
	 * <li>its_aid_ssp_list : ItsAidSsp
	 * <li>priority_its_aid_list : ItsAidPriority, Important only use this option for Version 1 certificates
	 * <li>priority_ssp_list : ItsAidPrioritySsp, Important only use this option for Version 1 certificates
	 * 
	 */
	public SubjectAttribute(SubjectAttributeType subjectAttributeType, List<Encodable> itsAidList) {
		if(subjectAttributeType != its_aid_list && 
		   subjectAttributeType != its_aid_ssp_list && 
		   subjectAttributeType != priority_its_aid_list &&
		   subjectAttributeType != priority_ssp_list){
			throw new IllegalArgumentException("Illegal subject attribute type, list of its aid values is only supported by types " + its_aid_list + ", " + its_aid_ssp_list  + ", " + priority_its_aid_list+ " and " + priority_ssp_list + ".");
		}
		this.subjectAttributeType = subjectAttributeType;
		this.itsAidList = itsAidList;
	}
	


	/**
	 * Constructor used during serializing
	 * 
	 */
	public SubjectAttribute(){
	}

	/**
	 * 
	 * @return the type of subject attribute type.
	 */
	public SubjectAttributeType getSubjectAttributeType() {
		return subjectAttributeType;
	}

	/**
	 * 
	 * @return returns public key if type is verification_key or encryption_key otherwise null.
	 */
	public PublicKey getPublicKey() {
		return key;
	}

	/**
	 * 
	 * @return returns the reconstructon value if the type is reconstruction_value, otherwise null.
	 */
	public EccPoint getReconstructionValue() {
		return rv;
	}

	/**
	 * 
	 * @return returns the subject assurance if type is assurance_level, otherwise null.
	 */
	public SubjectAssurance getSubjectAssurance() {
		return assuranceLevel;
	}

	/**
	 * 
	 * @return returns list of its aid values if type is one of its_aid_list, its_aid_ssp_list, priority_its_aid_list, priority_ssp_list, otherwise null. 
	 * the type of the returned list is for type:
	 * <li>its_aid_list : IntX
	 * <li>its_aid_ssp_list : ItsAidSsp
	 * <li>priority_its_aid_list : ItsAidPriority, Important only use this option for Version 1 certificates
	 * <li>priority_ssp_list : ItsAidPrioritySsp, Important only use this option for Version 1 certificates
	 */
	public List<Encodable> getItsAidList() {
		return itsAidList;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		out.write(subjectAttributeType.getByteValue());
		switch (subjectAttributeType) {
		case verification_key:
		case encryption_key:
			key.encode(out);
			break;
        case reconstruction_value:
        	rv.encode(out);
			break;
        case assurance_level:
        	assuranceLevel.encode(out);
			break;
        case its_aid_list:
        case its_aid_ssp_list:
        case priority_its_aid_list:
        case priority_ssp_list:
        	EncodeHelper.encodeVariableSizeVector(out, itsAidList);
			break;
		default:
			break;
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void decode(DataInputStream in) throws IOException {
		subjectAttributeType = SubjectAttributeType.getByValue(in.readByte());
		switch (subjectAttributeType) {
		case verification_key:
		case encryption_key:
			key = new PublicKey();
			key.decode(in);
			break;
        case reconstruction_value:
        	// TODO currently unsupported.
        	//rv = new EccPoint(publicKeyAlgorithm);
			break;
        case assurance_level:
        	assuranceLevel = new SubjectAssurance();
        	assuranceLevel.decode(in);
			break;
        case its_aid_list:
        	itsAidList = (List<Encodable>) EncodeHelper.decodeVariableSizeVector(in, IntX.class);
			break;
        case its_aid_ssp_list:
        	itsAidList =(List<Encodable>) EncodeHelper.decodeVariableSizeVector(in, ItsAidSsp.class);
			break;
        case priority_its_aid_list:
        	itsAidList =(List<Encodable>) EncodeHelper.decodeVariableSizeVector(in, ItsAidPriority.class);
			break;
        case priority_ssp_list:
        	itsAidList = (List<Encodable>) EncodeHelper.decodeVariableSizeVector(in, ItsAidPrioritySsp.class);
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
				+ ((assuranceLevel == null) ? 0 : assuranceLevel.hashCode());
		result = prime * result
				+ ((itsAidList == null) ? 0 : itsAidList.hashCode());
		result = prime * result + ((key == null) ? 0 : key.hashCode());
		result = prime * result + ((rv == null) ? 0 : rv.hashCode());
		result = prime
				* result
				+ ((subjectAttributeType == null) ? 0 : subjectAttributeType
						.hashCode());
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
		SubjectAttribute other = (SubjectAttribute) obj;
		if (assuranceLevel == null) {
			if (other.assuranceLevel != null)
				return false;
		} else if (!assuranceLevel.equals(other.assuranceLevel))
			return false;
		if (itsAidList == null) {
			if (other.itsAidList != null)
				return false;
		} else if (!itsAidList.equals(other.itsAidList))
			return false;
		if (key == null) {
			if (other.key != null)
				return false;
		} else if (!key.equals(other.key))
			return false;
		if (rv == null) {
			if (other.rv != null)
				return false;
		} else if (!rv.equals(other.rv))
			return false;
		if (subjectAttributeType != other.subjectAttributeType)
			return false;
		return true;
	}

	@Override
	public String toString() {
		switch (subjectAttributeType) {
		case verification_key:
		case encryption_key:
			return "SubjectAttribute [type=" + subjectAttributeType
					+ ", key=" + key.toString().replace("PublicKey ", "") +  "]";
        case reconstruction_value:
    		return "SubjectAttribute [type=" + subjectAttributeType
    				+ ", rv=" + rv.toString().replace("EccPoint ", "")  + "]";			
        case assurance_level:
    		return "SubjectAttribute [type=" + subjectAttributeType
    				+ ", assuranceLevel=" + assuranceLevel.toString().replace("SubjectAssurance ", "")  + "]";
        case its_aid_list:
        	return "SubjectAttribute [type=" + subjectAttributeType
    				+ ", itsAidList=" + EncodeHelper.listToString(itsAidList, "IntX ")  + "]";
        case its_aid_ssp_list:
        	return "SubjectAttribute [type=" + subjectAttributeType
    				+ ", itsAidList=" + EncodeHelper.listToString(itsAidList, "ItsAidSsp ")  + "]";
        case priority_its_aid_list:
        	return "SubjectAttribute [type=" + subjectAttributeType
    				+ ", itsAidList=" + EncodeHelper.listToString(itsAidList, "ItsAidPriority ")  + "]";
        case priority_ssp_list:
            return "SubjectAttribute [type=" + subjectAttributeType
				+ ", itsAidList=" + EncodeHelper.listToString(itsAidList, "ItsAidPrioritySsp ")  + "]";
    	
		default:
			return "SubjectAttribute [type=unknown]";
		}

	}




}
