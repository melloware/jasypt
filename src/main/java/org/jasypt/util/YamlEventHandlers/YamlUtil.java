package org.jasypt.util.YamlEventHandlers;

import java.io.StringReader;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.events.Event;
import org.yaml.snakeyaml.events.ScalarEvent;

/**
 * A utility class to keep static methods used multiple times in this package.
 * 
 * @author prakash.tiwari
 *
 */
public class YamlUtil {
	/**
	 * This method will give a snakeyaml scalar event from a String.
	 * 
	 * @param value
	 * @return
	 */
	public static Event getScalarEventFromString(String value) {
        Yaml yaml = new Yaml();
        for(Event e : yaml.parse(new StringReader(value))){
            if (e instanceof ScalarEvent) {
            	// Just a double check if we are indeed returning the desired event.
                if(value.equals( ((ScalarEvent) e).getValue() )) {
                	return e;
                }
            }
		}
        return null;
	}
}
