package org.certificateservices.custom.c2x.common.validator;

import org.certificateservices.custom.c2x.common.Certificate;
import java.util.Date;

public interface TimeValidator {

    /**
     * Method to verify that the given certificates are valid against the specified time.
     *
     * @param currentTime the expected time to verify the certificate against.
     * @param certificateChain the certificate to verify region in, end entity certificate first and root cert last.
     * @throws InvalidCertificateException if the given certificate chain was invalid for the specified time.
     * @throws IllegalArgumentException if other argument was invalid when validation the certificate.
     */
    void validateTime(Date currentTime, Certificate[] certificateChain) throws IllegalArgumentException, InvalidCertificateException;
}
