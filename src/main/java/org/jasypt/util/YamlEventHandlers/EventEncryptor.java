package org.jasypt.util.YamlEventHandlers;

import java.util.Properties;

import org.jasypt.intf.cli.JasyptEncryptorUtil;
import org.yaml.snakeyaml.events.Event;
import org.yaml.snakeyaml.events.ScalarEvent;

public class EventEncryptor {
	
	public Event encryptValueInScalarEvent(Event event, Properties argumentValues, JasyptEncryptorUtil encryptor) {
		String inputValue = ((ScalarEvent) event).getValue();
		if (inputValue.length() == 0) return event;
		String encryptedValue = encryptor.encrypt(inputValue);
		String encryptedValueWrapped = "ENC(" + encryptedValue + ")";
		((ScalarEvent) event).setValue(encryptedValueWrapped);
		return event;
	}
}
