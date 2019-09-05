package org.jasypt.util.filehandler;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Properties;

import org.apache.commons.io.FilenameUtils;
import org.jasypt.commons.CommonUtils;
import org.jasypt.intf.cli.JasyptEncryptorUtil;



public class SimpleSeparatedFileHandler implements FileHandler{
	String location = System.getProperty("user.dir") + "/";
	
	/*
	 * For lines where delimiter isn't present or there is no text after delimiter,
	 * we'll skip such lines.
	 */
	public String encryptFile(String fileName, Properties argumentValues) throws Exception{
		JasyptEncryptorUtil encryptor = new JasyptEncryptorUtil(argumentValues);
		
		String path = location + fileName;
		BufferedReader reader = new BufferedReader(new FileReader(path));
		
		String fileType = FilenameUtils.getExtension(fileName);
		String dot = (fileType.length()> 0)?("."):("");
		String output = "output"+ dot + fileType;
		path = location + output;
		FileWriter outputFile = new FileWriter(path);
		
		String delimiter = argumentValues.getProperty("delimiter");
		String line = reader.readLine();
		
		while (line != null) {
			if(line.contains(delimiter)) {
				String key = CommonUtils.substringBefore(line, delimiter);
				String value = CommonUtils.substringAfter(line, delimiter);
				value = value.trim();
				if(value.length()>0) {
					String encryptedValue = encryptor.encrypt(value);
					outputFile.write(key + delimiter + "ENC("+encryptedValue + ")\n");
				}
				else {
					outputFile.write(key + delimiter + "\n");
				}
			}
			else {
				outputFile.write(line + "\n");
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
		
		String delimiter = argumentValues.getProperty("delimiter");
		String line = reader.readLine();
		
		while (line != null) {
			if(line.contains(delimiter)) {
				String key = CommonUtils.substringBefore(line, delimiter);
				String value = CommonUtils.substringAfter(line, delimiter);
				value = value.trim();
				if(value.length()>0) value = unwrap(key, value);
				if(value.length()>0) {
					String decryptedValue = encryptor.decrypt(value);
					outputFile.write(key + delimiter + decryptedValue + "\n");
				}
				else {
					outputFile.write(key + delimiter + "\n");
				}
			}
			else {
				outputFile.write(line + "\n");
			}
			line = reader.readLine(); // read next line
		}
		reader.close();
		outputFile.close();
		
		return path;
	}
	
	private String unwrap(String key, String val){
		Exception exception = new Exception();
		try {
			if(val.length() < 5 || !val.substring(0, 4).equals("ENC(") || !val.substring(val.length() - 1).equals(")")) {
				throw exception;
			}
			String unwrapped = val.substring(4, val.length() - 1);
			return unwrapped;
		}
		catch(Exception e) {
			System.out.println("Ill formatted string recieved for decryption: \""+ val + "\" for key \"" + key + "\"."
					+ "Please note that the encrypted value must be prefixed with \"ENC(\" and suffixed with \")\"");
			return val;
		}
	}
}
