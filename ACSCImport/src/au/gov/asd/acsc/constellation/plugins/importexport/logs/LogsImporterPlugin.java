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
package au.gov.asd.acsc.constellation.plugins.importexport.logs;

import au.gov.asd.acsc.constellation.plugins.importexport.logs.eventparsers.EventTypeParser;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.TemporalConcept;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.Plugin;
import au.gov.asd.tac.constellation.plugins.PluginException;
import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameter;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.plugins.parameters.types.BooleanParameterType;
import au.gov.asd.tac.constellation.plugins.parameters.types.BooleanParameterType.BooleanParameterValue;
import au.gov.asd.tac.constellation.plugins.parameters.types.ObjectParameterType;
import au.gov.asd.tac.constellation.plugins.parameters.types.ObjectParameterType.ObjectParameterValue;
import au.gov.asd.tac.constellation.plugins.parameters.types.StringParameterType;
import au.gov.asd.tac.constellation.plugins.parameters.types.StringParameterValue;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import javafx.collections.ObservableList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.nifi.processors.evtx.RootNodeHandler;
import org.apache.nifi.processors.evtx.XmlRootNodeHandler;
import org.apache.nifi.processors.evtx.parser.ChunkHeader;
import org.apache.nifi.processors.evtx.parser.FileHeader;
import org.apache.nifi.processors.evtx.parser.MalformedChunkException;
import org.openide.util.Exceptions;
import org.openide.util.NbBundle;
import org.openide.util.lookup.ServiceProvider;
import org.openide.util.lookup.ServiceProviders;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

@ServiceProviders({
    @ServiceProvider(service = Plugin.class)
})
@NbBundle.Messages("LogsImporterPlugin=Import Logs")
public class LogsImporterPlugin extends RecordStoreQueryPlugin  {

    private static final Logger LOGGER = Logger.getLogger(LogsImporterPlugin.class.getName());

    /**
     * When an attribute is not assigned to a column, the value is -145355 so
     * its easier to track down if there is an error.
     */
    public static final int ATTRIBUTE_NOT_ASSIGNED_TO_COLUMN = -145355;

    public static final String FILEPATH_PARAMETER_ID = PluginParameter.buildId(LogsImporterPlugin.class, "path");
    public static final String SHOW_ALL_ID = PluginParameter.buildId(LogsImporterPlugin.class, "showAll");
    public static final String EVENTS_PARAMETER_ID = PluginParameter.buildId(LogsImporterPlugin.class, "events");

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();

        final PluginParameter<StringParameterValue> filePathParam = StringParameterType.build(FILEPATH_PARAMETER_ID);
        filePathParam.setName("File to parse");
        filePathParam.setDescription("File to parse");
        params.addParameter(filePathParam);
        
        final PluginParameter<ObjectParameterValue> eventsParam = ObjectParameterType.build(EVENTS_PARAMETER_ID);
        eventsParam.setName("Events To Parse");
        eventsParam.setDescription("Events To Parse");
        params.addParameter(eventsParam);
        
        final PluginParameter<BooleanParameterValue> showAllParam = BooleanParameterType.build(SHOW_ALL_ID);
        showAllParam.setName("Show All");
        showAllParam.setDescription("Show All");
        params.addParameter(showAllParam);

        return params;
    }


    @Override
    protected RecordStore query(RecordStore query, PluginInteraction interaction, PluginParameters parameters) throws InterruptedException, PluginException {
        final RecordStore results = new GraphRecordStore();
        
        //get parsers from object.
        final Map<String, PluginParameter<?>> params = parameters.getParameters();
        
        final ObservableList<EventTypeParser> querylist = (ObservableList<EventTypeParser>)parameters.getObjectValue(EVENTS_PARAMETER_ID);

        
        final String filepath =  parameters.getParameters().get(FILEPATH_PARAMETER_ID).getStringValue();
        final boolean showAll =  parameters.getParameters().get(SHOW_ALL_ID).getBooleanValue();
        try {
            try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(new File(filepath))))
            {
                
                FileHeader fileHeader = new FileHeader(in, null);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                try (RootNodeHandler rootNodeHandler = new XmlRootNodeHandler(out)) {
                    while (fileHeader.hasNext()) {
                        try {

                            ChunkHeader chunkHeader = fileHeader.next();
                            try {
                                while (chunkHeader.hasNext())
                                {
                                    rootNodeHandler.handle(chunkHeader.next().getRootNode());
                                }
                            } catch (Exception e1) {
                                e1.printStackTrace();
                            }

                        } catch (MalformedChunkException e2) {
                            e2.printStackTrace();
                        } 
                    }
                } catch (IOException e3) {
                    e3.printStackTrace();
                }

                DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();

                try {
                    DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
                    String a = new String(out.toByteArray());
                    String xml10pattern = "[^"
                            + "\u0009\r\n"
                            + "\u0020-\uD7FF"
                            + "\uE000-\uFFFD"
                            + "\ud800\udc00-\udbff\udfff"
                            + "]";

                    a = a.replaceAll(xml10pattern, ".");
                    ByteArrayInputStream bais = new ByteArrayInputStream(a.getBytes());

                    Document doc = dBuilder.parse(bais);
                    NodeList nl = doc.getElementsByTagName("Event");

                    HashMap<Integer, ArrayList<Element>> events = new HashMap<>();

                    for (int i=0;i< nl.getLength();i++)
                    {
                        Element n = (Element)nl.item(i);
                        boolean parsed = false;

                        
                        for (EventTypeParser p : querylist)
                        {
                            if (p.canParse(n))
                            {
                                p.parse(n, results, parameters);
                                parsed=true;
                            }
                        }
                        
                        if (!parsed && showAll)
                        {
                            Element system = (Element)n.getElementsByTagName("System").item(0);
                            Element eventData = (Element)n.getElementsByTagName("EventData").item(0);

                            int eventId = Integer.parseInt(((Element)system.getElementsByTagName("EventID").item(0)).getTextContent());
                            String providerName = ((Element)system.getElementsByTagName("Provider").item(0)).getAttribute("Name");
                            int eventRecordId = Integer.parseInt(((Element)system.getElementsByTagName("EventRecordID").item(0)).getTextContent());
                            String timeCreated = ((Element)system.getElementsByTagName("TimeCreated").item(0)).getAttribute("SystemTime");
                            String channel = ((Element)system.getElementsByTagName("Channel").item(0)).getTextContent();
                            String computer = ((Element)system.getElementsByTagName("Computer").item(0)).getTextContent();
                            results.add();
                            
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, eventRecordId);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, "Event");
                            results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.CREATED, TemporalFormatting.completeZonedDateTimeString(timeCreated));
                            results.set(GraphRecordStoreUtilities.SOURCE + "Provider Name", providerName);
                            results.set(GraphRecordStoreUtilities.SOURCE + "Channel", channel);
                            results.set(GraphRecordStoreUtilities.SOURCE + "Event Id", eventId);
                            
                            try {
                                Transformer transformer = TransformerFactory.newInstance().newTransformer();
                                transformer.setOutputProperty(OutputKeys.INDENT, "yes"); 
                                DOMSource source = new DOMSource(n);
                                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                                StreamResult console = new StreamResult(baos);

                                transformer.transform(source, console);

                                results.set(GraphRecordStoreUtilities.SOURCE + "XML", new String(baos.toByteArray()));
                            } catch (TransformerConfigurationException ex) {
                                Exceptions.printStackTrace(ex);
                            } catch (TransformerException ex) {
                                Exceptions.printStackTrace(ex);
                            }
                            
                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, computer);
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, "Computer"); 
                        }

                    }
                } 
                catch (SAXException | ParserConfigurationException ex) {
                    Exceptions.printStackTrace(ex);
                } 

            }

        } catch (FileNotFoundException ex) {
            Exceptions.printStackTrace(ex);
        } catch (IOException ex) {
            Exceptions.printStackTrace(ex);
        }
        return results;
    }
 
}
