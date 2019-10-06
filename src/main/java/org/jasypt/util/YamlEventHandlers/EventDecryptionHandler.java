package org.jasypt.util.YamlEventHandlers;

import java.io.FileWriter;
import java.util.Iterator;
import java.util.Properties;

import org.jasypt.intf.cli.JasyptEncryptorUtil;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.emitter.Emitter;
import org.yaml.snakeyaml.events.*;

/**
 * This class will handle decryption of yml file.
 * It should only be instantiated with the parameterized constructor {@link #EventDecryptionHandler(Iterator, Properties, String)}
 * <b>This class is for internal use only</b>.
 * 
 * @author prakash.tiwari
 *
 */
public class EventDecryptionHandler {
	
	private EventDecryptor eventDecryptor = new EventDecryptor();
	private JasyptEncryptorUtil encryptor;
	private Iterator <Event> eventItr;
	private Event currentEvent;
	private Emitter emitter;
	private Properties argumentValues;
	private String outputPath = null;
	public boolean success = true;
	
	public String getOutputPath() {
		if (success) return this.outputPath;
		else return null;
	}
	
	/**
	 * This constructor will accept a list of snakeyaml events serialized from a .yml file.
	 * We'll identify the scalar values with the help of helper functions and decrypt them.
	 * @param eventItr
	 * @param argumentValues
	 * @param location
	 * @throws Exception
	 */
	public EventDecryptionHandler(Iterator <Event> eventItr, Properties argumentValues, String location) throws Exception {
		this.encryptor = new JasyptEncryptorUtil(argumentValues);
		this.eventItr = eventItr;
		this.argumentValues = argumentValues;
		outputPath = location + "decryptedOutput.yml";
		FileWriter outputFile=new FileWriter(outputPath);
        this.emitter = new Emitter(outputFile, new DumperOptions());
		
		if (this.eventItr.hasNext()) {
			currentEvent = this.eventItr.next();
			if (currentEvent instanceof StreamStartEvent) {
				eventHandler();
			}
			else {
				success = false;
				throw new Exception("Sorry! We support events only from a stream.");
			}
		}
	}
	
	public void eventHandler() throws Exception{
		if(currentEvent instanceof StreamStartEvent) {
			streamHandler();
		}
		else if (currentEvent instanceof DocumentStartEvent) {
			documentHandler();
		}
		else if (currentEvent instanceof MappingStartEvent) {
			mappingHandler();
		}
		else if (currentEvent instanceof SequenceStartEvent) {
			sequenceHandler();
		}
		else if (currentEvent instanceof CollectionStartEvent) {
			collectionHandler();
		}
		return;
	}
	
	public void streamHandler() throws Exception{
		emitter.emit(currentEvent);
		currentEvent = eventItr.next();
		while(!(currentEvent instanceof StreamEndEvent)) { //Should I substitute "while" with "if"?
			eventHandler();
		}
		emitter.emit(currentEvent);
		if(eventItr.hasNext()) {
			currentEvent = eventItr.next();
			eventHandler();
		}
	}
	
	public void documentHandler() throws Exception{
		emitter.emit(currentEvent);
		currentEvent = eventItr.next();
		while(!(currentEvent instanceof DocumentEndEvent)) {
			eventHandler();
		}
		emitter.emit(currentEvent);
		if(eventItr.hasNext()) {
			currentEvent = eventItr.next();
			eventHandler();
		}
	}
	
	public void mappingHandler() throws Exception{
		emitter.emit(currentEvent);
		currentEvent = eventItr.next();
		boolean isValue = false;
		while(!(currentEvent instanceof MappingEndEvent)) {
			if(currentEvent instanceof ScalarEvent) {
				if(isValue) { 
					currentEvent = eventDecryptor.decryptValueInScalarEvent(currentEvent, argumentValues, encryptor); 
					isValue = false;
				}
				else {
					isValue = true;
				}
				emitter.emit(currentEvent);
				currentEvent = eventItr.next();
			}
			else {
				if(isValue) {
					isValue = false;
					eventHandler();
				}
			}
		}
		emitter.emit(currentEvent);
		if(eventItr.hasNext()) {
			currentEvent = eventItr.next();
			eventHandler();
		}
	}
	
	public void sequenceHandler() throws Exception{
		emitter.emit(currentEvent);
		currentEvent = eventItr.next();
		while (!(currentEvent instanceof SequenceEndEvent)) {
			if(currentEvent instanceof ScalarEvent) {
				currentEvent = eventDecryptor.decryptValueInScalarEvent(currentEvent, argumentValues, encryptor); 
				emitter.emit(currentEvent);
				currentEvent = eventItr.next();
			}
			else {
				eventHandler();
			}
		}
		emitter.emit(currentEvent);
		if(eventItr.hasNext()) {
			currentEvent = eventItr.next();
			eventHandler();
		}
	}
	
	public void collectionHandler() {
		
	}

}
