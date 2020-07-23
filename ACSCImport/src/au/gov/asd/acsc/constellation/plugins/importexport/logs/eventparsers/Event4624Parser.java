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
public class Event4624Parser extends EventTypeParser {

    private static final Logger LOGGER = Logger.getLogger(Event4624Parser.class.getName());

    public Event4624Parser() {
        super("4624 - Logon Types", 2);
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
        String user = dataPoints.getOrDefault("TargetUserName","Unknown");
        
        int logonType = Integer.parseInt(dataPoints.getOrDefault("LogonType","-1"));

        results.add();
        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, user);
        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.PERSON);
        
        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, computer);
        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, "Computer");
        
        results.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.VertexAttribute.IDENTIFIER, eventRecordId);
        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.TYPE, "Successful Logon");
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Channel", channel);
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Provider Name", providerName);
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Event ID", eventId);
        String lt;
        switch(logonType){
            case 2:
                lt = "Interactive";
                break;
            case 3:
                lt = "Network";
                break;
            case 4:
                lt = "Batch";
                break;
            case 5:
                lt = "Service";
                break;
            case 7:
                lt = "Unlock";
                break;
            case 8:
                lt = "Network Cleartext";
                break;
            case 9:
                lt = "New Credentials";
                break;
            case 10:
                lt = "Remote Interactive";
                break;
            case 11:
                lt = "Cached Interactive";
                break;
            default:
                lt = "Unknown";
        }
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Logon Type", lt);
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Logon Process Name",dataPoints.getOrDefault("LogonProcessName",null));
        
        results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, TemporalFormatting.completeZonedDateTimeString(timeCreated));
        
        
        // impersonation levels
        HashMap<String, String> levels = new HashMap<>();
        levels.put("%%1832","Identification");
        levels.put("%%1833","Impersonation");
        levels.put("%%1840","Delegation");
        levels.put("%%1841","Denied by Process Trust Label ACE");
        levels.put("%%1842","Yes");
        levels.put("%%1843","No");
        levels.put("%%1844","System");
        levels.put("%%1845","Not Available");
        levels.put("%%1846","Default");
        levels.put("%%1847","DisallowMmConfig");
        levels.put("%%1848","Off");
        levels.put("%%1849","Auto");
        String l =  dataPoints.getOrDefault("ImpersonationLevel","Unknown");

        results.set(GraphRecordStoreUtilities.TRANSACTION + "Impersonation Level", levels.getOrDefault(l,"Unknown"));
        
        
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes"); 
            DOMSource source = new DOMSource(input);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            StreamResult console = new StreamResult(baos);

            transformer.transform(source, console);
  
            results.set(GraphRecordStoreUtilities.TRANSACTION + "XML", new String(baos.toByteArray()));
        } catch (TransformerConfigurationException ex) {
            Exceptions.printStackTrace(ex);
        } catch (TransformerException ex) {
            Exceptions.printStackTrace(ex);
        }
        
        results.add();
        String ip = dataPoints.getOrDefault("IpAddress", null);
        if (ip != null && !ip.isBlank())
        {
            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, user);
            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.PERSON);
            
            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, ip);
            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, getIPType(ip));
            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.TYPE, "Logged in from");
        }
            
    }
    
    @Override
    public boolean canParse(Element input) throws IOException {
        Element system = (Element)input.getElementsByTagName("System").item(0);

        int eventId = Integer.parseInt(((Element)system.getElementsByTagName("EventID").item(0)).getTextContent());
        if (eventId == 4624)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
}