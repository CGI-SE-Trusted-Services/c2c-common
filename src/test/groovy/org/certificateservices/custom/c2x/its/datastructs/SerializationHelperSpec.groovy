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
package org.certificateservices.custom.c2x.its.datastructs

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.its.datastructs.cert.ItsAidSsp
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAssurance
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttribute;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectInfo;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType
import org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestriction;
import org.certificateservices.custom.c2x.its.datastructs.SerializationHelper;
import org.certificateservices.custom.c2x.its.datastructs.StructSerializer;
import org.junit.Before;

import spock.lang.Specification
import spock.lang.Unroll;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SerializationHelperSpec extends Specification {
	

   @Unroll	
   def "Verify encodeVariableSizeVector encodes #description"(){
	   setup:
	   ByteArrayOutputStream baos = new ByteArrayOutputStream()
	   DataOutputStream dos = new DataOutputStream(baos)
	   
	   when:
	   SerializationHelper.encodeVariableSizeVector(dos, vector) 
	   then:
	   getHex(baos) == expect
	   where:
	   description                               | expect                           | vector
	   "a small IntX vector properly"            | "03010203"                       | [new IntX(1),new IntX(2),new IntX(3)]
	   "an empty vector propery"                 | "00"                             | []
	   "an small ItsAidSsp vector propery"       | "0701010002020000"               | [new ItsAidSsp(new IntX(1), new byte[1]),new ItsAidSsp(new IntX(2), new byte[2])]	   
   }
   
   def "Verify encodeVariableSizeVector supports data larger that 127 bytes"(){
	   setup:
	   ByteArrayOutputStream baos = new ByteArrayOutputStream()
	   DataOutputStream dos = new DataOutputStream(baos)
	   
	   when:
	   SerializationHelper.encodeVariableSizeVector(dos,[new ItsAidSsp(new IntX(1), new byte[31]),new ItsAidSsp(new IntX(2), new byte[31]),new ItsAidSsp(new IntX(3), new byte[31]),new ItsAidSsp(new IntX(4), new byte[31]),new ItsAidSsp(new IntX(5), new byte[31]),new ItsAidSsp(new IntX(6), new byte[31])])
	   String result = getHex(baos)
	   
	   then:
	   result.length()/2 == 200
	   result.substring(0,4) == "80c6"
   }
   
   @Unroll
   def "Verify decodeVariableSizeVector decodes #description"(){
	   setup:
	   ByteArrayInputStream bais = new ByteArrayInputStream(Hex.decode(data))
	   DataInputStream dis = new DataInputStream(bais)
	   
	   when:
	   def result = SerializationHelper.decodeVariableSizeVector(dis, classType)
	   then:
	   result.size() == expectedSize
	   if(expectedSize > 0){
		   assert result[0].class == classType
	   }
	   where:
	   description                             | expectedSize | data                            | classType
	   "a small IntX vector properly"          | 3            | "03010203"                      | IntX.class
	   "an empty vector propery"               | 0            | "00"                            | Object.class
	   "an small ItsAidSsp vector propery"     | 2            | "0701010002020000"              | ItsAidSsp.class 
   }
   
   def "Verify decodeVariableSizeVector supports data larger that 127 bytes"(){
	   setup:
	   ByteArrayOutputStream baos = new ByteArrayOutputStream()
	   DataOutputStream dos = new DataOutputStream(baos)
	   SerializationHelper.encodeVariableSizeVector(dos,[new ItsAidSsp(new IntX(1), new byte[31]),new ItsAidSsp(new IntX(2), new byte[31]),new ItsAidSsp(new IntX(3), new byte[31]),new ItsAidSsp(new IntX(4), new byte[31]),new ItsAidSsp(new IntX(5), new byte[31]),new ItsAidSsp(new IntX(6), new byte[31])])
	   String data = getHex(baos)
	   ByteArrayInputStream bais = new ByteArrayInputStream(Hex.decode(data))
	   DataInputStream dis = new DataInputStream(bais)
	   when:
	   def result = SerializationHelper.decodeVariableSizeVector(dis,ItsAidSsp.class );
	   	   
	   then:
	   result.size() == 6
	   result[0].itsAid.value.intValue() == 1
	   result[1].itsAid.value.intValue()  == 2
	   result[2].itsAid.value.intValue()  == 3
	   result[3].itsAid.value.intValue()  == 4
	   result[4].itsAid.value.intValue()  == 5
	   result[5].itsAid.value.intValue()  == 6
   }
   
   private String getHex(ByteArrayOutputStream baos){
	   new String(Hex.encode(baos.toByteArray()));
   }

}
