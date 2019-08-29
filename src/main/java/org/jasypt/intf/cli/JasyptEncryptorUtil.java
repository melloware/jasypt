package org.jasypt.intf.cli;

import java.util.Properties;

import org.jasypt.intf.cli.ArgumentNaming;
import org.jasypt.intf.service.JasyptStatelessService;

public class JasyptEncryptorUtil {
	private String password = null;
	private String algorithm = null;
	private String keyObtentionIterations = null;
	private String saltGeneratorClassName = null;
	private String providerName = null;
	private String providerClassName = null;
	private String stringOutputType = null;
	
	private JasyptStatelessService service = new JasyptStatelessService();
	
	public JasyptEncryptorUtil(Properties argumentValues) {
		password = argumentValues.getProperty(ArgumentNaming.ARG_PASSWORD);
		algorithm = argumentValues.getProperty(ArgumentNaming.ARG_ALGORITHM);
		keyObtentionIterations = argumentValues.getProperty(ArgumentNaming.ARG_KEY_OBTENTION_ITERATIONS);
		saltGeneratorClassName = argumentValues.getProperty(ArgumentNaming.ARG_SALT_GENERATOR_CLASS_NAME);
		providerName = argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_NAME);
		providerClassName = argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_CLASS_NAME);
		stringOutputType = argumentValues.getProperty(ArgumentNaming.ARG_STRING_OUTPUT_TYPE);
		
	}
	
	public String encrypt(String input) {
		String result =
				service.encrypt(
	                    input, 
	                    password,
	                    null,
	                    null,
	                    algorithm,
	                    null,
	                    null,
	                    keyObtentionIterations,
	                    null,
	                    null,
	                    saltGeneratorClassName,
	                    null,
	                    null,
	                    providerName,
	                    null,
	                    null,
	                    providerClassName,
	                    null,
	                    null,
	                    stringOutputType,
	                    null,
	                    null);
		
		
		return result;
	}
	
	public String decrypt(String input) {
		final JasyptStatelessService service = new JasyptStatelessService();
		
		String result =
	            service.decrypt(
	                    input, 
	                    password,
	                    null,
	                    null,
	                    algorithm,
	                    null,
	                    null,
	                    keyObtentionIterations,
	                    null,
	                    null,
	                    saltGeneratorClassName,
	                    null,
	                    null,
	                    providerName,
	                    null,
	                    null,
	                    providerClassName,
	                    null,
	                    null,
	                    stringOutputType,
	                    null,
	                    null);
		
		return result;
	}
}
