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
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.crowdstrike;

import au.gov.asd.acsc.constellation.preferences.ACSCPreferenceKeys;
import au.gov.asd.acsc.constellation.schema.cyberschema.concept.CyberConcept;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.ContentConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.TemporalConcept;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.Plugin;
import au.gov.asd.tac.constellation.plugins.PluginException;
import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.PluginNotificationLevel;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import java.util.HashMap;
import java.util.prefs.Preferences;
import org.json.JSONArray;
import org.json.JSONObject;
import org.openide.util.NbBundle.Messages;
import org.openide.util.NbPreferences;
import org.openide.util.lookup.ServiceProvider;
import org.openide.util.lookup.ServiceProviders;

@ServiceProviders({
    @ServiceProvider(service = DataAccessPlugin.class)
    ,
    @ServiceProvider(service = Plugin.class)
})
@Messages("CrowdstrikePlugin=CrowdStrike")
public class CrowdstrikePlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {

    @Override
    public String getType() {
        return DataAccessPluginCoreType.ENRICHMENT;
    }

    @Override
    public int getPosition() {
        return Integer.MAX_VALUE - 10;
    }

    @Override
    public String getDescription() {
        return "CrowdStrike";
    }

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();
  
        return params;
    }

    private String getTypeFromString(String type)
    {
        HashMap<String,String> mapping = new HashMap<>();
        mapping.put("binary_string", CyberConcept.VertexType.STRING.getName());
        mapping.put("compile_time", "Compile Time");
        mapping.put("device_name", "Device Name");
        mapping.put("domain", AnalyticConcept.VertexType.HOST_NAME.getName());
        mapping.put("email_address", AnalyticConcept.VertexType.EMAIL_ADDRESS.getName());
        mapping.put("email_subject", "Email Subject");
        mapping.put("event_name", "Event Name");
        mapping.put("file_mapping", "File Mapping");
        mapping.put("file_name", "File Name");
        mapping.put("file_path", "File Path");
        mapping.put("hash_ion", AnalyticConcept.VertexType.HASH.getName());
        mapping.put("hash_md5", AnalyticConcept.VertexType.MD5.getName());
        mapping.put("hash_sha1", AnalyticConcept.VertexType.SHA1.getName());
        mapping.put("hash_sha256", AnalyticConcept.VertexType.SHA256.getName());
        mapping.put("ip_address", AnalyticConcept.VertexType.IP_ADDRESS.getName());
        mapping.put("ip_address_block", "CIDR");
        mapping.put("mutex_name", "Mutex Name");
        mapping.put("password", "Password");
        mapping.put("persona_name", "Persona Name");
        mapping.put("phone_number", AnalyticConcept.VertexType.TELEPHONE_IDENTIFIER.getName());
        mapping.put("port", "Port"); 
        mapping.put("registry", "Registry");
        mapping.put("semaphore_name", "Semaphore Name");
        mapping.put("service_name", CyberConcept.VertexType.SERVICE.getName());
        mapping.put("url", AnalyticConcept.VertexType.URL.getName());
        mapping.put("user_agent", "User Agent");
        mapping.put("username", AnalyticConcept.VertexType.USER_NAME.getName());
        mapping.put("x509_seria", "x509 Seria");
        mapping.put("x509_seria1", "x509 Seria1");
        mapping.put("x509_subject", "x509 Subject");
        return mapping.getOrDefault(type, type);
    }
    
    private void drawIndicatorResults(RecordStore results, PluginInteraction interaction, String identifier, String type, JSONArray res, CrowdstrikeClient client)
    {
        for (Object o : res)
        {
            JSONObject match = (JSONObject)o;

            results.add();
            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
            if (match.has("last_updated") && match.get("last_updated") != null)
            {
                results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.MODIFIED, TemporalFormatting.zonedDateTimeStringFromLong(match.getLong("last_updated")*1000));
            }
            if (match.has("published_date") && match.get("published_date") != null)
            {
                results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.CREATED, TemporalFormatting.zonedDateTimeStringFromLong(match.getLong("published_date")*1000));
            }
            if (match.has("malicious_confidence") && match.get("malicious_confidence") != null)
            {
                results.set(GraphRecordStoreUtilities.SOURCE + "Malicious Confidence", match.getString("malicious_confidence"));
            }
            if (match.has("kill_chains") && match.get("kill_chains") != null && match.getJSONArray("kill_chains").length() > 0)
            {
                results.set(GraphRecordStoreUtilities.SOURCE + "Kill Chains", match.getJSONArray("kill_chains").join("\n"));                        
            }
            if (match.has("labels") && match.get("labels") != null && match.getJSONArray("labels").length() > 0)
            {
                String labelVal = "";
                for (Object lbl : match.getJSONArray("labels"))
                {
                    JSONObject l = (JSONObject)lbl;
                    labelVal += l.getString("name") + "\n";
                }
                labelVal = labelVal.trim();
                results.set(GraphRecordStoreUtilities.SOURCE + "Labels",labelVal);                        
            }

            if (match.has("reports") && match.get("reports") != null)
            {
                for (Object report : match.getJSONArray("reports"))
                {
                    JSONObject reportData = client.searchReportName((String)report, interaction);
                    if (reportData != null)
                    {
                        for (Object r : reportData.getJSONArray("resources"))
                        {
                            JSONObject rep = (JSONObject)r;

                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, rep.getString("name"));
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.DOCUMENT);
                            results.set(GraphRecordStoreUtilities.DESTINATION + ContentConcept.VertexAttribute.DESCRIPTION , rep.getString("short_description"));
                            results.set(GraphRecordStoreUtilities.DESTINATION + ContentConcept.VertexAttribute.URL , rep.getString("url"));

                        }  
                    }
                    else
                    {
                        results.add();
                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, report);
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.DOCUMENT);
                    }
                }
            }

            if (match.has("actors") && match.get("actors") != null)
            {
                for (Object a : match.getJSONArray("actors"))
                {
                    String actor = (String)a;
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                    JSONObject actorObj = client.getActor(actor, interaction);
                    if (actorObj != null)
                    {
                        JSONArray actors = actorObj.getJSONArray("resources");
                        for (Object b : actors)
                        {
                            JSONObject ao = (JSONObject)b;
                            String name = ao.getString("name");
                            String desc = ao.getString("description");

                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);  


                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, name);
                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.LABEL, name+ "<" + CyberConcept.VertexType.INTRUSION_SET.getName() +">" );
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.RAW, name+ "<" + CyberConcept.VertexType.INTRUSION_SET.getName() +">");
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.INTRUSION_SET);
                            results.set(GraphRecordStoreUtilities.DESTINATION + ContentConcept.VertexAttribute.DESCRIPTION, desc );
                            results.set(GraphRecordStoreUtilities.DESTINATION + "Capability", ao.getJSONObject("capability").getString("value") );
                            results.set(GraphRecordStoreUtilities.DESTINATION + "Known as", ao.getString("known_as"));
                            results.set(GraphRecordStoreUtilities.DESTINATION + ContentConcept.VertexAttribute.URL, ao.getString("url") );
                        }
                    }
                }
            }

            if (match.has("malware_families") && match.get("malware_families") != null)
            {
                for (Object family : match.getJSONArray("malware_families"))
                {
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                    results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, family);
                    results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.CODE_FAMILY);
                }
            }

            if (match.has("relations") && match.get("relations") != null)
            {
                for (Object rel : match.getJSONArray("relations"))
                {
                    JSONObject relation = (JSONObject)rel;
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                    results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, relation.getString("indicator"));

                    results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, getTypeFromString(relation.getString("type")));
                    results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.CREATED, TemporalFormatting.zonedDateTimeStringFromLong(relation.getLong("created_date")*1000));
                    results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.LAST_SEEN, TemporalFormatting.zonedDateTimeStringFromLong(relation.getLong("last_valid_date")*1000));

                }
            }
        }
    }
    
    private void searchHostname(RecordStore results, PluginInteraction interaction, CrowdstrikeClient client, String identifier, String type )
    {
        JSONArray res = client.searchDomain(identifier, interaction);
        if (res != null)
        {
            drawIndicatorResults(results, interaction, identifier, type, res, client);
        }
    }
    
    private void searchIPAddress(RecordStore results, PluginInteraction interaction, CrowdstrikeClient client, String identifier, String type )
    {
        JSONArray res = client.searchIPAddress(identifier, interaction);
        if (res != null)
        {
            drawIndicatorResults(results, interaction, identifier, type, res, client);
        }
    }
    
    private void searchHash(RecordStore results, PluginInteraction interaction, CrowdstrikeClient client, String identifier, String type )
    {
        JSONArray res = client.searchHash(identifier, interaction);
        if (res != null)
        {
            drawIndicatorResults(results, interaction, identifier, type, res, client);
        }
    }
    
    private void searchEmailAddress(RecordStore results, PluginInteraction interaction, CrowdstrikeClient client, String identifier, String type )
    {
        JSONArray res = client.searchEmailAddress(identifier, interaction);
        if (res != null)
        {
            drawIndicatorResults(results, interaction, identifier, type, res, client);
        }
    }
    
    private void searchUrl(RecordStore results, PluginInteraction interaction, CrowdstrikeClient client, String identifier, String type )
    {
        JSONArray res = client.searchUrl(identifier, interaction);
        if (res != null)
        {
            drawIndicatorResults(results, interaction, identifier, type, res, client);
        }
    }
    
    private void searchGeneric(RecordStore results, PluginInteraction interaction, CrowdstrikeClient client, String identifier, String type )
    {
        JSONArray res = client.searchHash(identifier, interaction);
        if (res != null)
        {
            drawIndicatorResults(results, interaction, identifier, type, res, client);
        }
    }
    
    private void searchActor(RecordStore results, PluginInteraction interaction, CrowdstrikeClient client, String identifier, String type )
    {
        JSONArray res = client.searchActor(identifier, interaction);
        if (res != null)
        {
            drawIndicatorResults(results, interaction, identifier, type, res, client);
        }
    }
    
    @Override
    protected RecordStore query(final RecordStore query, final PluginInteraction interaction, final PluginParameters parameters) throws PluginException {

        final RecordStore results = new GraphRecordStore();
        final Preferences prefs = NbPreferences.forModule(ACSCPreferenceKeys.class);
        String secret = prefs.get(ACSCPreferenceKeys.CROWDSTRIKE_SECRET, null);
        String username = prefs.get(ACSCPreferenceKeys.CROWDSTRIKE_USERNAME, null);
        
        if ((secret == null || secret.isEmpty()) || (username == null || username.isEmpty() )) {
            interaction.notify(PluginNotificationLevel.FATAL, "The API key or username has not been set.\nPlease update these at Setup > Options > CONSTELLATION > ACSC > CrowdStrike");
            return results;
        }

        if (query.size() == 0) {
            return results;
        }
        
        query.reset();
        
        
        CrowdstrikeClient client  = new CrowdstrikeClient(secret, username);
        while (query.next()) {
            
            String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
            String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);
            if (type.equals(AnalyticConcept.VertexType.IPV4.toString())
                    || type.equals(AnalyticConcept.VertexType.IPV6.toString())
                    || type.equals(AnalyticConcept.VertexType.IP_ADDRESS.toString())) {
                searchIPAddress(results, interaction, client, identifier, type); 
            }
            else if (type.equals(AnalyticConcept.VertexType.HOST_NAME.toString())) {
                searchHostname(results, interaction, client, identifier, type); 
            }
            else if (type.equals(AnalyticConcept.VertexType.HASH.toString()) ||
                    type.equals(AnalyticConcept.VertexType.MD5.toString())  ||
                    type.equals(AnalyticConcept.VertexType.SHA1.toString())  ||    
                    type.equals(AnalyticConcept.VertexType.SHA256.toString())  ||
                    type.equals(AnalyticConcept.VertexType.MD5.toString())) {
                searchHash(results, interaction, client, identifier, type);
            }
            else if (type.equals(AnalyticConcept.VertexType.EMAIL_ADDRESS.toString())) {
                searchEmailAddress(results, interaction, client, identifier, type);
                
            }
            else if (type.equals(AnalyticConcept.VertexType.URL.toString())) {
                searchUrl(results, interaction, client, identifier, type);
                
            }
            else if (type.equals(CyberConcept.VertexType.INTRUSION_SET.toString())) {
                searchActor(results, interaction, client, identifier, type);
            }
            else
            {
                searchGeneric(results, interaction, client, identifier, type);
            }
        }
        return results;
    }
}
