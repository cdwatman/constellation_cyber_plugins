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
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.domaintools;

import au.gov.asd.acsc.constellation.preferences.ACSCPreferenceKeys;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.SpatialConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.TemporalConcept;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.Plugin;
import au.gov.asd.tac.constellation.plugins.PluginException;
import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.PluginNotificationLevel;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameter;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.plugins.parameters.types.MultiChoiceParameterType;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
@Messages("DomainToolsPlugin=DomainTools Whois")
public class DomainToolsPlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {

    public static final String QUERY_PARAMETER_ID = PluginParameter.buildId(DomainToolsPlugin.class, "queries");

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
        return "DomainTools enrichment";
    }

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();
        
        final PluginParameter queries = MultiChoiceParameterType.build(QUERY_PARAMETER_ID);
        queries.setName("Queries");
        ArrayList<String> hashPivots = new ArrayList<>();
        
        hashPivots.add("Whois");
        hashPivots.add("Profile");
        hashPivots.sort(null);
        
        MultiChoiceParameterType.setOptions(queries, hashPivots);
        
        MultiChoiceParameterType.setChoices(queries, new ArrayList<>());
        params.addParameter(queries);
        
        return params;
    }
    
    private boolean whoisIP(String identifier, String type, DomainToolsClient client, RecordStore results, PluginInteraction interaction)
    {
        JSONObject res = client.searchWhois(identifier, interaction);
        if (res != null)
        {
            if (res.has("response"))
            {
                JSONObject response  = res.getJSONObject("response");
                String registrant = response.getString("registrant");
                JSONObject parsedWhois = response.getJSONObject("parsed_whois");
                JSONObject whois = response.getJSONObject("whois");
                String source = response.getString("source");
                String recordSource = response.getString("record_source");

                results.add();
                results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                results.set(GraphRecordStoreUtilities.SOURCE + "Whois", whois.get("record"));
                results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.DATETIME, TemporalFormatting.completeZonedDateTimeString((String)whois.get("date")));
                JSONArray networks = parsedWhois.getJSONArray("networks");
                for (Object o : networks)
                {
                    JSONObject net =(JSONObject)o;
                    JSONArray cidrs = net.getJSONObject("range").getJSONArray("cidr");
                    for (Object c : cidrs)
                    {
                        results.add();
                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, (String)c);
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, "CIDR");

                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.COMMENT, net.getJSONArray("descr").join("\n"));
                        results.set(GraphRecordStoreUtilities.DESTINATION + "Name", net.get("name"));
                        if (net.has("created_date") && net.get("created_date") != null && !net.getString("created_date").isEmpty())
                        {
                            results.set(GraphRecordStoreUtilities.DESTINATION + TemporalConcept.VertexAttribute.CREATED , TemporalFormatting.completeZonedDateTimeString(net.getString("created_date")));
                        }
                        if (net.has("updated_date") && net.get("updated_date") != null && !net.getString("updated_date").isEmpty())
                        {
                            results.set(GraphRecordStoreUtilities.DESTINATION + TemporalConcept.VertexAttribute.CREATED , TemporalFormatting.completeZonedDateTimeString(net.getString("updated_date")));
                        }

                    }
                }
                JSONArray contacts = parsedWhois.getJSONArray("contacts");
                for (Object c : contacts)
                {
                    JSONObject contact = (JSONObject)c;
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                    String name = contact.getString("id");
                    if (contact.has("name") && contact.get("name") != null && !contact.getString("name").isEmpty())
                    {
                        name = contact.getString("name");
                    }
                    results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, name);
                    results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.PERSON);
                    results.set(GraphRecordStoreUtilities.DESTINATION + "Address", contact.getJSONArray("address").join(" "));
                    for (Object p : contact.getJSONArray("phone"))
                    {
                        results.add();
                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, name);
                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.PERSON);
                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, (String)p);
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.TELEPHONE_IDENTIFIER);
                    }
                    for (Object p : contact.getJSONArray("email"))
                    {
                        results.add();
                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, name);
                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.PERSON);
                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, (String)p);
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.EMAIL_ADDRESS);
                    }
                }
            }
            return true;
        }
        else
        {
            return false;
        }
    }
    
    private boolean profileDomain(String identifier, String type, DomainToolsClient client, RecordStore results, PluginInteraction interaction)
    {
        JSONObject res = client.searchProfile(identifier, interaction);
        if (res != null)
        {
            if (res.has("response"))
            {
                JSONObject response  = res.getJSONObject("response");
                JSONObject data = null;
                
                if (response.has("server"))
                {
                    data = response.getJSONObject("server");
                    if (data.has("ip_address") && data.get("ip_address") != null && !data.getString("ip_address").isEmpty())
                    {
                        results.add();
                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, data.getString("ip_address"));
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.IPV4);
                    }
                }
                if (response.has("website_data"))
                {
                    data = response.getJSONObject("website_data");
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                    if (data.has("server") && data.get("server")!= null)
                    {
                        results.set(GraphRecordStoreUtilities.SOURCE + "Server", data.get("server"));
                    }
                    if (data.has("title") && data.get("title")!= null)
                    {
                        results.set(GraphRecordStoreUtilities.SOURCE + "Page Title", data.get("title"));
                    }
                    
                }
                if (response.has("registrant"))
                {
                    data = response.getJSONObject("registrant");
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                    if (data.has("name") && data.get("name") != null)
                    {
                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, data.getString("name"));
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.PERSON);
                        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, "Registrant");
                    }
                }
            }
            return true;
        }
        else
        {
            return false;
        }
    }

    private boolean whoisDomain(String identifier, String type, DomainToolsClient client, RecordStore results, PluginInteraction interaction)
    {
        JSONObject res = client.searchWhois(identifier, interaction);
        if (res != null)
        {
            if (res.has("response"))
            {
                JSONObject response  = res.getJSONObject("response");
                JSONObject parsedWhois = response.getJSONObject("parsed_whois");
                JSONObject whois = response.getJSONObject("whois");


                results.add();
                results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                results.set(GraphRecordStoreUtilities.SOURCE + "Whois", whois.get("record"));
                results.set(GraphRecordStoreUtilities.SOURCE + "Whois Date", TemporalFormatting.completeZonedDateTimeString((String)whois.get("date")));
                results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.CREATED, TemporalFormatting.completeZonedDateTimeString((String)parsedWhois.get("created_date")));
                results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.MODIFIED, TemporalFormatting.completeZonedDateTimeString((String)parsedWhois.get("updated_date")));
                results.set(GraphRecordStoreUtilities.SOURCE + "Expires", TemporalFormatting.completeZonedDateTimeString((String)parsedWhois.get("expired_date")));

                JSONObject contacts = parsedWhois.getJSONObject("contacts");
                for (Object c : contacts.keySet())
                {
                    String contactType = (String)c;
                    JSONObject contact = contacts.getJSONObject(contactType);

                    if ( (contact.get("country") != null && !contact.getString("country").isEmpty()) ||
                         (contact.get("org") != null && !contact.getString("org").isEmpty()) ||
                         (contact.get("city") != null && !contact.getString("city").isEmpty()) ||
                         (contact.get("phone") != null && !contact.getString("phone").isEmpty()) ||
                         (contact.get("street") != null && !contact.getJSONArray("street").isEmpty()) ||
                         (contact.get("name") != null && !contact.getString("name").isEmpty()) ||
                         (contact.get("state") != null && !contact.getString("state").isEmpty()) ||
                         (contact.get("postal") != null && !contact.getString("postal").isEmpty()) ||
                         (contact.get("fax") != null && !contact.getString("fax").isEmpty()) ||
                         (contact.get("email") != null && !contact.getString("email").isEmpty()))
                    {

                        results.add();
                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                        String name = String.format("%s contact", contactType);

                        if (contact.has("name") && contact.get("name") != null && !contact.getString("name").isEmpty())
                        {
                            name = contact.getString("name");
                        }
                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, name);
                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.PERSON);
                        if (contact.get("country") != null && !contact.getString("country").isEmpty())
                        {
                            results.set(GraphRecordStoreUtilities.DESTINATION + SpatialConcept.VertexAttribute.COUNTRY, contact.getString("country"));
                        }
                        if (contact.get("org") != null && !contact.getString("org").isEmpty())
                        {
                            results.set(GraphRecordStoreUtilities.DESTINATION + "Organisation", contact.getString("org"));
                        }
                        if (contact.get("city") != null && !contact.getString("city").isEmpty())
                        {
                            results.set(GraphRecordStoreUtilities.DESTINATION + SpatialConcept.VertexAttribute.CITY, contact.getString("city"));
                        }
                        if (contact.get("street") != null && !contact.getJSONArray("street").isEmpty())
                        {
                            results.set(GraphRecordStoreUtilities.DESTINATION + "Steet", contact.getJSONArray("street").join(" "));
                        }
                        if (contact.get("state") != null && !contact.getString("state").isEmpty())
                        {
                            results.set(GraphRecordStoreUtilities.DESTINATION + "State", contact.getString("state"));
                        }
                        if (contact.get("postal") != null && !contact.getString("postal").isEmpty())
                        {
                            results.set(GraphRecordStoreUtilities.DESTINATION + "Postal", contact.getString("postal"));
                        }
                        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, contactType);

                        if (contact.get("phone") != null && !contact.getString("phone").isEmpty())
                        {
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, name);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.PERSON);
                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, contact.getString("phone"));
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.TELEPHONE_IDENTIFIER);
                            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, "Phone");
                        }

                        if (contact.get("fax") != null && !contact.getString("fax").isEmpty())
                        {
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, name);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.PERSON);
                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, contact.getString("fax"));
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.TELEPHONE_IDENTIFIER);
                            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, "Fax");
                        }

                        if (contact.get("email") != null && !contact.getString("email").isEmpty())
                        {
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, name);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.PERSON);
                            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, contact.getString("email"));
                            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.EMAIL_ADDRESS);
                        }
                    }
                }

                if (response.has("registrant") && response.get("registrant") != null && !response.getString("registrant").isEmpty())
                {
                    results.add();
                    results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                    results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                    results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, response.getString("registrant"));
                    results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.ORGANISATION);
                    results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, "Registrant");
                }
                
            }
            return true;
        }
        else
        {
            return false;
        }
    }

    @Override
    protected RecordStore query(final RecordStore query, final PluginInteraction interaction, final PluginParameters parameters) throws PluginException {

        final RecordStore results = new GraphRecordStore();
        final Preferences prefs = NbPreferences.forModule(ACSCPreferenceKeys.class);
        String apiKey = prefs.get(ACSCPreferenceKeys.DOMAINTOOLS_API_KEY, null);
        String username = prefs.get(ACSCPreferenceKeys.DOMAINTOOLS_USERNAME, null);

        if ((apiKey == null || apiKey.isEmpty()) || (username == null || username.isEmpty() )) {
            interaction.notify(PluginNotificationLevel.FATAL, "The API key or username has not been set.\nPlease update these at Setup > Options > CONSTELLATION > ACSC > DomainTools");
            return results;
        }

        if (query.size() == 0) {
            return results;
        }
        
        query.reset();
        final Map<String, PluginParameter<?>> params = parameters.getParameters();
        
        final MultiChoiceParameterType.MultiChoiceParameterValue querylist = parameters.getMultiChoiceValue(QUERY_PARAMETER_ID);

        List<String> queries = querylist.getChoices();
        
        DomainToolsClient client  = new DomainToolsClient(apiKey, username);
        while (query.next()) {
            
            String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
            String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);
            if (type.equals(AnalyticConcept.VertexType.IPV4.toString())
                    || type.equals(AnalyticConcept.VertexType.IPV6.toString())
                    || type.equals(AnalyticConcept.VertexType.IP_ADDRESS.toString())) {
                
                if (queries.contains("Whois") && !whoisIP(identifier, type, client, results, interaction))
                {
                    break;
                }
                
            }
            if (type.equals(AnalyticConcept.VertexType.HOST_NAME.toString())) {
                
                if (queries.contains("Whois") && !whoisDomain(identifier, type, client, results, interaction))
                {
                    break;
                }
                if (queries.contains("Profile") && !profileDomain(identifier, type, client, results, interaction))
                {
                    break;
                }
            }
        }
        return results;
    }

}
