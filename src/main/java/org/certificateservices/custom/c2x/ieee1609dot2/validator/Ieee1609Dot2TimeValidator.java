/************************************************************************
 *                                                                       *
 *  Certificate Service - Car2Car Core                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.custom.c2x.ieee1609dot2.validator;

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.validator.InvalidCertificateException;
import org.certificateservices.custom.c2x.common.validator.TimeValidator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;

import java.util.Calendar;
import java.util.Date;

/**
 * Time validator for IEEE 1609.2 Certificates.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class Ieee1609Dot2TimeValidator implements TimeValidator {
    /**
     * Method to verify that the given certificates are valid against the specified time.
     *
     * @param currentTime      the expected time to verify the certificate against.
     * @param certificateChain the certificate to verify region in, end entity certificate first and root cert last.
     * @param entireChain if entireChain should be validated or only first certificate in chain.
     * @throws InvalidCertificateException if the given certificate chain was invalid for the specified time.
     * @throws BadArgumentException    if other argument was invalid when validation the certificate.
     */
    @Override
    public void validateTime(Date currentTime, org.certificateservices.custom.c2x.common.Certificate[] certificateChain,
                             boolean entireChain) throws BadArgumentException, InvalidCertificateException {
        Certificate[] chain;
        if(entireChain){
            chain = BaseCertificateValidator.toIEEE1609Certificates(certificateChain);
        }else{
            chain = new Certificate[] {(org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate) certificateChain[0]};
        }

        for(Certificate certificate : chain){
            ValidityPeriod validityPeriod = certificate.getToBeSigned().getValidityPeriod();
            Date startDate = validityPeriod.getStart().asDate();
            if(currentTime.before(startDate)){
                throw new InvalidCertificateException("Invalid certificate in chain, not yet valid.");
            }
            Date endDate = toEndDate(startDate, validityPeriod.getDuration());
            if(currentTime.after(endDate)){
                throw new InvalidCertificateException("Expired certificate exists in chain.");
            }
        }
    }

    /**
     * Method to get the end date of a certificate from its start date and duration.
     * @param startDate the start date to calculate end date from
     * @param duration the duration to add to the start date.
     * @return a calculated end date.
     * @throws InvalidCertificateException if duration contained invalid parameters, such as microseconds unit.
     */
    public Date toEndDate(Date startDate, Duration duration) throws InvalidCertificateException {
        Date retval;
        if(duration.getUnit() == Duration.DurationChoices.years){
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(startDate);
            calendar.add(Calendar.YEAR, duration.getValueAsInt());
            retval = calendar.getTime();
        }else{
            retval = new Date(startDate.getTime() + durationAsMS(duration));
        }
        return retval;
    }

    /**
     * Help method to convert durations that is not microseconds or years to milliseconds (unsupported)
     * @param duration the duration to convert to milliseconds.
     * @return the duration in milliseconds
     * @throws InvalidCertificateException if duration was specified in microseconds.
     */
    protected long durationAsMS(Duration duration) throws InvalidCertificateException{
        long value = duration.getValueAsInt();
        switch (duration.getUnit()){
            case microseconds:
                throw new InvalidCertificateException("Invalid validity period in certificate, duration unit of microseconds is not supported.");
            case milliseconds:
                return value;
            case seconds:
                return value * 1000L;
            case minutes:
                return value * 60000L; // 60 * 1000
            case hours:
                return value * 3600000L; // 60 * 60 * 100
            case sixtyHours:
                return value * 216000000L; // 60 * 60 * 60 * 100
            case years:
                assert false : "Invalid call to durationAsMS, year units should be handled by different call"; // This should never
        }
        throw new InvalidCertificateException("Unsupported duration found in certificate: " + duration.getUnit());
    }

}
