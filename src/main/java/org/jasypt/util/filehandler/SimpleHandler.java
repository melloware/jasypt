package org.jasypt.util.filehandler;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;

public class SimpleHandler {
	String location = System.getProperty("user.dir");
	
	public ArrayList <String> getListFromSimpleFile(String fileName) throws Exception{
		ArrayList <String> input  = new ArrayList<String>();
		String path = location + fileName;
		BufferedReader reader = new BufferedReader(new FileReader(path));
		
		String line = reader.readLine();
		
		while (line != null) {
			// read next line
			input.add(line);
			line = reader.readLine();
		}
		reader.close();
		
		return input;
	}
	
	public String writeListToSimpleFile(ArrayList <String> list) throws Exception{
		String path = location + "output.txt";
		FileWriter outputFile = new FileWriter(path);
		for (String value: list) {
			outputFile.write(value);
		}
		outputFile.close();
		
		return path;
	}
}
