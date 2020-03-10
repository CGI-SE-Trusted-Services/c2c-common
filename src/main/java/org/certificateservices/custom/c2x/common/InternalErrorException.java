package org.certificateservices.custom.c2x.common;

/**
 * Class indicating and internal error in application, due to configuration other problems
 *
 * @author Philip 2019-06-18
 */
public class InternalErrorException extends Exception{

    /**
     * Class indicating and internal error in application, due to configuration other problems.
     * @param message descriptive error message of the error.
     */
    public InternalErrorException(String message) {
        super(message);
    }

    /**
     * Class indicating and internal error in application, due to configuration other problems.
     *
     * @param message descriptive error message of the error.
     * @param cause cause of the exception
     */
    public InternalErrorException(String message, Throwable cause) {
        super(message, cause);
    }
}
