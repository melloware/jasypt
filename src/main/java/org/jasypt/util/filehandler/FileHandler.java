package org.jasypt.util.filehandler;

import java.util.Properties;

/*
 * The interface which will be implemented to handle different types of file decryption.
 */

public interface FileHandler {
	public String encryptFile(String fileName, Properties argumentValues) throws Exception;
	public String decryptFile(String fileName, Properties argumentValues) throws Exception;
}
