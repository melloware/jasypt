package org.jasypt.util.filehandler;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Properties;

import org.apache.commons.io.FilenameUtils;
import org.jasypt.intf.cli.JasyptEncryptorUtil;

/**
 * This class will handle encryption/decryption of simple files.</br>
 * Encryption/Decryption is done on a line-by-line basis and the whole line is encrypted.
 * <b>This class is for internal use only</b>.
 * 
 * @author prakash.tiwari
 * 
 */
public class SimpleHandler implements FileHandler {
	String location = System.getProperty("user.dir") + "/";
	
	public String encryptFile(String fileName, Properties argumentValues) throws Exception{
		JasyptEncryptorUtil encryptor = new JasyptEncryptorUtil(argumentValues);
		
		String path = location + fileName;
		BufferedReader reader = new BufferedReader(new FileReader(path));
		
		String fileType = FilenameUtils.getExtension(fileName);
		String dot = (fileType.length()> 0)?("."):("");
		String output = "output"+ dot + fileType;
		path = location + output;
		FileWriter outputFile = new FileWriter(path);
		
		String line = reader.readLine();
		while (line != null) {
			line.trim();
			if(line.length()>0) {
				String encryptedValue = encryptor.encrypt(line);
				outputFile.write(encryptedValue + "\n");
			}
			else {
				outputFile.write("\n");
			}
			line = reader.readLine(); // read next line
		}
		reader.close();
		outputFile.close();
		
		return path;
	}
	
	public String decryptFile(String fileName, Properties argumentValues) throws Exception{
		JasyptEncryptorUtil encryptor = new JasyptEncryptorUtil(argumentValues);
		
		String path = location + fileName;
		BufferedReader reader = new BufferedReader(new FileReader(path));
		
		String fileType = FilenameUtils.getExtension(fileName);
		String dot = (fileType.length()> 0)?("."):("");
		String output = "decryptedOutput"+ dot + fileType;
		path = location + output;
		FileWriter outputFile = new FileWriter(path);
		
		String line = reader.readLine();
		while (line != null) {
			line.trim();
			if(line.length()>0) {
				String decryptedValue = encryptor.decrypt(line);
				outputFile.write(decryptedValue + "\n");
			}
			else {
				outputFile.write("\n");
			}
			line = reader.readLine(); // read next line
		}
		reader.close();
		outputFile.close();
		
		return path;
	}
}
