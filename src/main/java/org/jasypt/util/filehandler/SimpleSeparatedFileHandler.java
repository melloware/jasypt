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
	
	public String encryptFile(String fileName, Properties argumentValues) throws Exception{
		JasyptEncryptorUtil encryptor = new JasyptEncryptorUtil(argumentValues);
		
		String path = location + fileName;
		path = "/Users/prakash.tiwari/Desktop/" + fileName;
		BufferedReader reader = new BufferedReader(new FileReader(path));
		
		String fileType = FilenameUtils.getExtension(fileName);
		String dot = (fileType.length()> 0)?("."):("");
		String output = "output"+ dot + fileType;
		path = location + output;
		path = "/Users/prakash.tiwari/Desktop/" + output;
		FileWriter outputFile = new FileWriter(path);
		
		String delimiter = argumentValues.getProperty("delimiter");
		String line = reader.readLine();
		
		while (line != null) {
			String key = CommonUtils.substringBefore(line, delimiter);
			String value = CommonUtils.substringAfter(line, delimiter);
			value = value.trim();
			String encryptedValue = encryptor.encrypt(value);
			outputFile.write(key + delimiter + "ENC("+encryptedValue + ")\n");
			line = reader.readLine(); // read next line
		}
		reader.close();
		outputFile.close();
		
		return path;
	}
}
