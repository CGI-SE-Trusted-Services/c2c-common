package org.certificateservices.custom.c2x.ecc

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security;

import org.bouncycastle.crypto.tls.CertificateURL;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.ecc.ECQV.CertReq;

import spock.lang.Specification;
import spock.lang.Unroll;

class MinimalFixedFieldCertificateSpec extends Specification{


	def "Verify constructor and getters and setters"(){
		when:
		def cert = new MinimalFixedFieldCertificate("TestU".getBytes("UTF-8"), "TestPU".getBytes("UTF-8"))
		
		then:
		new String(cert.getPU(),"UTF-8") == "TestPU"
		new String(cert.getU(),"UTF-8") == "TestU"
		cert.toString() == "MinimalFixedFieldCertificate [U=5465737455, PU=546573745055]"
	}
	
	def "Verify serialize and deserialize"(){
		setup:
		def cert1 = new MinimalFixedFieldCertificate("TestU".getBytes("UTF-8"), "TestPU".getBytes("UTF-8"))
		
		when:
		byte[] data =  cert1.getEncoded();
		
		then:
		new String(Hex.encode(data)) == "05546573745506546573745055"
		
		when:
		def cert2 = new MinimalFixedFieldCertificate(data)
		
		then:
		new String(cert2.getPU(),"UTF-8") == "TestPU"
		new String(cert2.getU(),"UTF-8") == "TestU"
		
	}
	

}
