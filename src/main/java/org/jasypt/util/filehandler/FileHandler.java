package org.jasypt.util.filehandler;

import java.util.Properties;

public interface FileHandler {
	public String encryptFile(String fileName, Properties argumentValues) throws Exception;
}
