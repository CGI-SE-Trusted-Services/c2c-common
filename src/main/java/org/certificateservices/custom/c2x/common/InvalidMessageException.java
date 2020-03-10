package org.certificateservices.custom.c2x.common;


/**
 * Exception thrown if a service received invalid message data and an error response should be returned to sender.
 *
 * @author Philip Vendil 2019-09-03
 */
public class InvalidMessageException extends Exception {

    private Object errorCode;

    /**
     * Exception thrown if a service received invalid message data.
     * @param message a descriptive error message.
     * @param errorCode an error code used in message response, the type of object depends on category of request message
     * such as EnrollmentResponseCode if request was an Enrollment Request etc.
     */
    public  InvalidMessageException(String message, Object errorCode){
        this(message,errorCode,null);
    }

    /**
     * Exception thrown if a service received invalid message data.
     * @param message a descriptive error message.
     * @param errorCode an error code used in message response, the type of object depends on category of request message
     * such as EnrollmentResponseCode if request was an Enrollment Request etc.
     * @param cause optional cause of this exception.
     */
    public InvalidMessageException(String message, Object errorCode, Throwable cause){
        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     *
     * @return an error code used in message response, the type of object depends on category of request message
     * such as EnrollmentResponseCode if request was an Enrollment Request etc.
     */
    public Object getErrorCode() {
        return errorCode;
    }

}
