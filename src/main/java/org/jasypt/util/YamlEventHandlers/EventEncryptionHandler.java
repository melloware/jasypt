package org.jasypt.util.YamlEventHandlers;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;
import java.util.Properties;

import org.jasypt.intf.cli.JasyptEncryptorUtil;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.emitter.Emitter;
import org.yaml.snakeyaml.events.*;

public class EventEncryptionHandler {
	
	private EventEncryptor eventEncryptor = new EventEncryptor();
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
	
	public EventEncryptionHandler(Iterator <Event> eventItr, Properties argumentValues, String location) throws IOException {
		this.encryptor = new JasyptEncryptorUtil(argumentValues);
		this.eventItr = eventItr;
		this.argumentValues = argumentValues;
		outputPath = location + "output.yml";
		FileWriter outputFile=new FileWriter(outputPath);
        this.emitter = new Emitter(outputFile, new DumperOptions());
		
		if (this.eventItr.hasNext()) {
			currentEvent = this.eventItr.next();
			Exception exception = new Exception("Sorry! We support events only from a stream.");
			try {
				if (currentEvent instanceof StreamStartEvent) {
					eventHandler();
				}
				else {
					throw exception;
				}
			}
			catch(Exception e) {
				success = false;
				System.out.println(e);
			}
		}
	}
	
	public void eventHandler(){
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
	
	public void streamHandler(){
		try {
			emitter.emit(currentEvent);
			currentEvent = eventItr.next();
			while(!(currentEvent instanceof StreamEndEvent)) { //Should I substitue "while" with "if"?
				eventHandler();
			}
			emitter.emit(currentEvent);
			if(eventItr.hasNext()) {
				currentEvent = eventItr.next();
				eventHandler();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void documentHandler(){
		try {
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
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void mappingHandler(){
		try {
			emitter.emit(currentEvent);
			currentEvent = eventItr.next();
			boolean isValue = false;
			while(!(currentEvent instanceof MappingEndEvent)) {
				if(currentEvent instanceof ScalarEvent) {
					if(isValue) {
						currentEvent = eventEncryptor.encryptValueInScalarEvent(currentEvent, argumentValues, encryptor);
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
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void sequenceHandler(){
		try {
			emitter.emit(currentEvent);
			currentEvent = eventItr.next();
			while (!(currentEvent instanceof SequenceEndEvent)) {
				if(currentEvent instanceof ScalarEvent) { 
					currentEvent = eventEncryptor.encryptValueInScalarEvent(currentEvent, argumentValues, encryptor);
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
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void collectionHandler() {
		
	}
}
