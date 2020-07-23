/*
 * Copyright 2010-2020 Australian Signals Directorate
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package au.gov.asd.acsc.constellation.plugins.importexport.logs.eventparsers;

import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.TemporalConcept;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Logger;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.openide.util.Exceptions;
import org.openide.util.lookup.ServiceProvider;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

@ServiceProvider(service = EventTypeParser.class)
public class Event4688Parser extends EventTypeParser {

    private static final Logger LOGGER = Logger.getLogger(Event4688Parser.class.getName());

    public Event4688Parser() {
        super("4688 - New Process Created", 2);
    }

    @Override
    public void parse(Element input, RecordStore results, PluginParameters parameters) throws IOException {        
        Element system = (Element)input.getElementsByTagName("System").item(0);
        Element eventData = (Element)input.getElementsByTagName("EventData").item(0);

        int eventId = Integer.parseInt(((Element)system.getElementsByTagName("EventID").item(0)).getTextContent());
        String providerName = ((Element)system.getElementsByTagName("Provider").item(0)).getAttribute("Name");
        int eventRecordId = Integer.parseInt(((Element)system.getElementsByTagName("EventRecordID").item(0)).getTextContent());
        String timeCreated = ((Element)system.getElementsByTagName("TimeCreated").item(0)).getAttribute("SystemTime");
        String channel = ((Element)system.getElementsByTagName("Channel").item(0)).getTextContent();
        String computer = ((Element)system.getElementsByTagName("Computer").item(0)).getTextContent();
        
        
        HashMap<String,String> dataPoints = new HashMap<>();
        NodeList nl = eventData.getElementsByTagName("Data");
        for (int i=0;i<nl.getLength();i++)
        {
            Element dp = (Element)nl.item(i);
            dataPoints.put(dp.getAttribute("Name"), dp.getTextContent());
        }
        String newProcessId = dataPoints.getOrDefault("NewProcessId","Unknown");
        String newProcessName = dataPoints.getOrDefault("NewProcessName","Unknown");
        String commandLine = dataPoints.getOrDefault("CommandLine","Unknown");
        String parentProcessId = dataPoints.getOrDefault("ProcessId","Unknown");
        String elevationToken = dataPoints.getOrDefault("ElevationTokenType","Unknown");
        String userName = dataPoints.getOrDefault("SubjectUserName","Unknown");
        String et;
        switch(elevationToken){
            case "%%1936":
                et = "Type 1";
                break;
            case "%%1937":
                et = "Type 2";
                break;
            case "%%1938":
                et = "Type 3";
                break;
            default:
                et = "Unknown : " + elevationToken;
        }
        

        results.add();
        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, newProcessId);
        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, "Process");
        results.set(GraphRecordStoreUtilities.SOURCE + "Process Name", newProcessName);
        results.set(GraphRecordStoreUtilities.SOURCE + "Command Line", commandLine);
        results.set(GraphRecordStoreUtilities.SOURCE + "Parent Process", parentProcessId);
        results.set(GraphRecordStoreUtilities.SOURCE + "Token Elevation Type", et);
        results.set(GraphRecordStoreUtilities.SOURCE + "Computer Name", computer);
        results.set(GraphRecordStoreUtilities.SOURCE + "User Name", userName);
        
        results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.CREATED, TemporalFormatting.completeZonedDateTimeString(timeCreated));

        
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes"); 
            DOMSource source = new DOMSource(input);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            StreamResult console = new StreamResult(baos);

            transformer.transform(source, console);
  
            results.set(GraphRecordStoreUtilities.SOURCE + "XML", new String(baos.toByteArray()));
        } catch (TransformerConfigurationException ex) {
            Exceptions.printStackTrace(ex);
        } catch (TransformerException ex) {
            Exceptions.printStackTrace(ex);
        }

        if (parentProcessId != null && !parentProcessId.isBlank() && !parentProcessId.equalsIgnoreCase("Unknown"))
        {
            results.add();

            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, newProcessId);
            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, "Process");

            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, parentProcessId);
            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, "Process");
            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.TYPE, "Parent Process");
        }
        
    }

    
    @Override
    public boolean canParse(Element input) throws IOException {
        Element system = (Element)input.getElementsByTagName("System").item(0);

        int eventId = Integer.parseInt(((Element)system.getElementsByTagName("EventID").item(0)).getTextContent());
        if (eventId == 4688)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
}
