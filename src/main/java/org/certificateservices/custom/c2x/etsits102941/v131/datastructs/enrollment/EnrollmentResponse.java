package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;

import java.io.IOException;

/**
 * TODO
 */
public class EnrollmentResponse extends COERSequence {

    private static final int RESPONSECODE = 0;
    private static final int CONFIRMEDSUBJECTATTRIBUTES = 1;

    /**
     * Constructor used when decoding
     */
    public EnrollmentResponse(){
        super(true,2);
        init();
    }

    /**
     * Constructor used when encoding
     */
    public EnrollmentResponse(EnrollmentResponseCode responseCode,
                                           CertificateSubjectAttributes confirmedSubjectAttributes) throws IOException {
        super(true,2);
        init();
        if(responseCode == null){
            throw new IOException("Illegal argument: responseCode cannot be null for EnrollmentResponse");
        }
        if(confirmedSubjectAttributes != null && confirmedSubjectAttributes.getCertIssuePermissions() != null){
            throw new IOException("Invalid confirmedSubjectAttributes in EnrollmentResponse, certIssuePermissions cannot be set.");
        }

        set(RESPONSECODE, new COEREnumeration(responseCode));
        set(CONFIRMEDSUBJECTATTRIBUTES, confirmedSubjectAttributes);
    }

    /**
     *
     * @return responseCode value
     */
    public EnrollmentResponseCode getResponseCode(){
        return (EnrollmentResponseCode) ((COEREnumeration) get(RESPONSECODE)).getValue();
    }

    /**
     *
     * @return confirmedSubjectAttributes value
     */
    public CertificateSubjectAttributes getConfirmedSubjectAttributes(){
        return (CertificateSubjectAttributes) get(CONFIRMEDSUBJECTATTRIBUTES);
    }

    private void init(){
        addField(RESPONSECODE, false, new COEREnumeration(EnrollmentResponseCode.class), null);
        addField(CONFIRMEDSUBJECTATTRIBUTES, true, new CertificateSubjectAttributes(), null);
    }

    @Override
    public String toString() {
        String attrString = "NONE";
        if(getConfirmedSubjectAttributes() != null){
            attrString = getConfirmedSubjectAttributes().toString().replaceAll("CertificateSubjectAttributes ","").replaceAll("\n","\n  ");
        }
        return "EnrollmentResponse [\n" +
                "  responseCode=" + getResponseCode()  + "\n" +
                "  confirmedSubjectAttributes=" + attrString + "\n" +
                "]";
    }
}