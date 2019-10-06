package org.jasypt.util.filehandler;

import java.io.FileReader;
import java.util.Iterator;
import java.util.Properties;

import org.jasypt.util.YamlEventHandlers.EventDecryptionHandler;
import org.jasypt.util.YamlEventHandlers.EventEncryptionHandler;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.events.Event;

/**
 * This class will handle encryption/decryption of yml files.
 * Encryption/Decryption will be done after parsing the whole document in key-value type and only the scalar values will be ecnrypted/decrypted.
 * For lines where delimiter isn't present or there is no text after delimiter, we'll skip such lines.
 * <b>This class is for internal use only</b>.
 * 
 * @author prakash.tiwari
 *
 */
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
	
	/**
	 * Encrypted values must be prefixed with "ENC(" and suffixed with ")"
	 */
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
