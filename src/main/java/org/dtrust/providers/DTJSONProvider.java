package org.dtrust.providers;

import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.Provider;

import org.codehaus.jackson.jaxrs.JacksonJsonProvider;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.SerializationConfig;
import org.springframework.stereotype.Component;

@Provider
@Consumes({MediaType.APPLICATION_JSON, "text/json"})
@Produces({MediaType.APPLICATION_JSON, "text/json"})
@Component
public class DTJSONProvider extends JacksonJsonProvider 
{
	/**
	 * {@inheritDoc}
	 */
	public DTJSONProvider()
	{        
		super(getDefaultObjectMapper());
	}
	
	/**
	 * {@inheritDoc}
	 */
	///CLOVER:OFF
	public DTJSONProvider(ObjectMapper mapper) 
    {
        super(mapper);
    }
	///CLOVER:ON
	
	/*
	 * Create the custom, default object mapper.
	 */
	public static ObjectMapper getDefaultObjectMapper()
	{
		ObjectMapper mappy = new ObjectMapper();
	    mappy.configure(SerializationConfig.Feature.WRITE_DATES_AS_TIMESTAMPS, false);
	    mappy.configure(SerializationConfig.Feature.FAIL_ON_EMPTY_BEANS, false);
	    
	    return mappy;
	}
}
