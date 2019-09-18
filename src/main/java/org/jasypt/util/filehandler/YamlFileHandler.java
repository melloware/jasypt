package org.jasypt.util.filehandler;

import java.io.FileReader;
import java.util.Iterator;
import java.util.Properties;

import org.jasypt.util.YamlEventHandlers.EventDecryptionHandler;
import org.jasypt.util.YamlEventHandlers.EventEncryptionHandler;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.events.Event;


public class YamlFileHandler implements FileHandler{
	String location = System.getProperty("user.dir") + "/";
	
	public String encryptFile(String fileName, Properties argumentValues) throws Exception{
		
		Yaml yaml = new Yaml();
		String path = location + fileName;
        FileReader contentFromFile=new FileReader(path);
        Iterable<Event> eventList = yaml.parse(contentFromFile);
        Iterator <Event> eventItr = eventList.iterator();
        
        EventEncryptionHandler yamlEncrypt = new EventEncryptionHandler(eventItr, argumentValues, location);
		
        String outputPath = yamlEncrypt.getOutputPath();
		return outputPath;
	}
	
	public String decryptFile(String fileName, Properties argumentValues) throws Exception{
		
		Yaml yaml = new Yaml();
		String path = location + fileName;
        FileReader contentFromFile=new FileReader(path);
        Iterable<Event> eventList = yaml.parse(contentFromFile);
        Iterator <Event> eventItr = eventList.iterator();
        
        EventDecryptionHandler yamlDecrypt = new EventDecryptionHandler(eventItr, argumentValues, location);
		
        String outputPath = yamlDecrypt.getOutputPath();
		return outputPath;
	}
}
