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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CountryOnly;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IdentifiedRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfIdentifiedRegion;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;

import java.util.ArrayList;
import java.util.List;

import static org.certificateservices.custom.c2x.ieee1609dot2.validator.BaseCertificateValidator.isSelfSigned;

/**
 * Implementation of a RegionValidatior that only supports identified region containing country only as type.
 * All other are disregarded with an InvalidCertificateException.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class CountryOnlyRegionValidator extends BaseRegionValidator {

    /**
     * Method to verify that the region in certificate matches the requirement in the
     * issuer certificate. If certificate is self-signed it ignore the certificate.
     *
     * @param checkRegion the expected region to validate the certificate for.
     * @param certificateChain the certificate to verify region in, end entity certificate first and root cert last.
     * @throws InvalidCertificateException if region in given certificate was invalid.
     * @throws BadArgumentException    if other argument was invalid not related to the region in the certificate.
     */
    @Override
    public void validateRegion(GeographicRegion checkRegion, org.certificateservices.custom.c2x.common.Certificate[] certificateChain) throws BadArgumentException, InvalidCertificateException {
        try {
            isValidRegionType(checkRegion);
        }catch(InvalidCertificateException e){
            throw new BadArgumentException("Invalid argument, acceptedRegion must be of type identifiedRegion containing only countryOnly.");
        }
        Certificate[] chain = BaseCertificateValidator.toIEEE1609Certificates(certificateChain);
        if(chain.length == 1 ){
            if(isSelfSigned(chain[0])){
                // Only check the root ca for accepted countries.
                allCountriesAreAccepted(getCountryIds(checkRegion),getCountryIds(getRegion(chain[0])));
                return;
            }else{
                throw new InvalidCertificateException("Invalid certificate chain, top most certificate must be a root certificate.");
            }
        }
        if(!isSelfSigned(chain[chain.length-1])){
            throw new InvalidCertificateException("Invalid certificate chain, top most certificate must be a root certificate.");
        }

        List<Long>  endCertificateCountryIds = null;

        // First traverse the regions in the chain
        for(int i=chain.length-2;i>=0;i--){
            Certificate cert = chain[i];
            Certificate issuer = chain[i+1];
            GeographicRegion issuerRegion = getRegion(issuer);
            isValidRegionType(issuerRegion);
            if(issuerRegion == null){
                continue; // The region in issuer is valid world wide
            }
            GeographicRegion certRegion = getRegion(cert);

            if(certRegion == null){
                endCertificateCountryIds = getCountryIds(issuerRegion);
            }else{
                isValidRegionType(certRegion);
                List<Long> certCountryIds = getCountryIds(certRegion);
                allCountriesAreAccepted(certCountryIds,getCountryIds(issuerRegion));
                if(i == 0){
                    endCertificateCountryIds = certCountryIds;
                }
            }
        }

        allCountriesAreAccepted(getCountryIds(checkRegion),endCertificateCountryIds);

    }


    /**
     * Method that checks that all checked country ids exists in certificates country ids
     * @param certCountryIds the country codes from the certificate, if null is all accepted
     * @param checkedCountryIds the country codes to check, if null is all accepted
     * @throws InvalidCertificateException if the exists at least one checked country code doesn't exist in certificate.
     */
    void allCountriesAreAccepted(List<Long> certCountryIds, List<Long> checkedCountryIds) throws InvalidCertificateException{
        if(checkedCountryIds == null || certCountryIds == null){
            return; // world wide acceptance.
        }
        if(!checkedCountryIds.containsAll(certCountryIds)){
            throw new InvalidCertificateException("Invalid set of countryOnly ids in certificate.");
        }
    }

    /**
     * Method that goes through the region and verifies only type CountryOnly exists.
     * @param regions the GeographicRegion to check
     * @throws InvalidCertificateException if invalid region was found.
     */
    private void isValidRegionType(GeographicRegion regions) throws InvalidCertificateException {
        if(regions == null){
            return;
        }
        if(regions.getType() != GeographicRegion.GeographicRegionChoices.identifiedRegion){
            throw new InvalidCertificateException("Invalid region in certificate, only identifiedRegion is supported not " + regions.getType() + ".");
        }
        SequenceOfIdentifiedRegion acceptedIdentifiedRegions = (SequenceOfIdentifiedRegion) regions.getValue();
        for(Object next : acceptedIdentifiedRegions.getSequenceValues()){
            IdentifiedRegion identifiedRegion = (IdentifiedRegion) next;
            if(identifiedRegion.getType() != IdentifiedRegion.IdentifiedRegionChoices.countryOnly){
                throw new InvalidCertificateException("Invalid region in certificate, only identifiedRegion with sequence of country only is supported not " + identifiedRegion.getType() + ".");
            }
        }
    }

    /**
     * Help method to convert all regions countryOnly ids for a region into a list of integers (country code).
     * @param regions the regions field to convert.
     * @return a list of country code ids, or null if no region exists.
     */
    private List<Long> getCountryIds(GeographicRegion regions){
        List<Long> retval = null;
        if(regions != null) {
            retval = new ArrayList<>();
            SequenceOfIdentifiedRegion regionList = (SequenceOfIdentifiedRegion) regions.getValue();
            for (Object next : regionList.getSequenceValues()) {
                IdentifiedRegion identifiedRegion = (IdentifiedRegion) next;
                CountryOnly countryOnly = (CountryOnly) identifiedRegion.getValue();
                retval.add(countryOnly.getValueAsLong());
            }
        }
        return retval;
    }
}
