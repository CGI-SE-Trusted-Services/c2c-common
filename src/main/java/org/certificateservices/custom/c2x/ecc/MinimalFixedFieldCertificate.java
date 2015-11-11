package org.certificateservices.custom.c2x.ecc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;

public class MinimalFixedFieldCertificate {
	
	byte[] U;
	byte[] PU;
	
	public MinimalFixedFieldCertificate(byte[] U, byte[] PU){
		this.U = U;
		this.PU = PU;
	}
	
	public MinimalFixedFieldCertificate(byte[] encoded) throws IOException{
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(encoded));
		IntX sizeU = new IntX();
		sizeU.deserialize(dis);
		U = new byte[sizeU.getValue().intValue()];
		dis.read(U);
		
		IntX sizePU = new IntX();
		sizePU.deserialize(dis);
		PU = new byte[sizePU.getValue().intValue()];
		dis.read(PU);
	}
	
	public byte[] getU(){
		return U;
	}
	
	public byte[] getPU(){
		return PU;
	}
	
	public byte[] getEncoded() throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		IntX sizeU = new IntX(U.length);
		sizeU.serialize(dos);
		dos.write(U);
		
		IntX sizePU = new IntX(PU.length);
		sizePU.serialize(dos);
		
		dos.write(PU);
		
		dos.close();
		return baos.toByteArray();
	}
	
	@Override
	public String toString() {
		return "MinimalFixedFieldCertificate [U=" + new String(Hex.encode(U))
				+ ", PU=" + new String(Hex.encode(PU)) + "]";
	}

}
