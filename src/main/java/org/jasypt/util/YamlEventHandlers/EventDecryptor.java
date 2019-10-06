package org.jasypt.util.YamlEventHandlers;

import java.util.Properties;

import org.jasypt.intf.cli.JasyptEncryptorUtil;
import org.yaml.snakeyaml.events.Event;
import org.yaml.snakeyaml.events.ScalarEvent;

/**
 * This class'll do decryption of value in a Scalar event.
 * <b>This class is for internal use only</b>.
 * 
 * @author prakash.tiwari
 *
 */
public class EventDecryptor {
	public Event decryptValueInScalarEvent(Event event, Properties argumentValues, JasyptEncryptorUtil encryptor) throws Exception{
		String inputValue = ((ScalarEvent) event).getValue();
		if (inputValue.length() == 0) return event;
		else {
			inputValue = unwrap(inputValue);
		}
		String decryptedValue = encryptor.decrypt(inputValue);
		Event newEvent = YamlUtil.getScalarEventFromString(decryptedValue);
		return newEvent;
	}
	
	/**
	 * Utility method to remove "ENC()" from a wrapped encrypted string
	 * 
	 * @param val
	 * @return
	 */
	private String unwrap(String val){
		if(val.length() < 5 || !val.substring(0, 4).equals("ENC(") || !val.substring(val.length() - 1).equals(")")) {
			System.out.println("Ill formatted string recieved for decryption: \""+ val + "\"."
					+ "Please note that the encrypted value must be prefixed with \"ENC(\" and suffixed with \")\"");
			return val;
		}
		String unwrapped = val.substring(4, val.length() - 1);
		return unwrapped;
	}
}
