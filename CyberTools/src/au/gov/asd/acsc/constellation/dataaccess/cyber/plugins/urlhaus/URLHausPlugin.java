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
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.urlhaus;

import au.gov.asd.acsc.constellation.schema.cyberschema.concept.CyberConcept;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.TemporalConcept;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.Plugin;
import au.gov.asd.tac.constellation.plugins.PluginException;
import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.PluginNotificationLevel;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.security.proxy.ConstellationHttpProxySelector;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.openide.util.Exceptions;
import org.openide.util.NbBundle.Messages;
import org.openide.util.lookup.ServiceProvider;
import org.openide.util.lookup.ServiceProviders;

@ServiceProviders({
    @ServiceProvider(service = DataAccessPlugin.class)
    ,
    @ServiceProvider(service = Plugin.class)
})
@Messages("URLHausPlugin=URLhaus")
public class URLHausPlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {

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
        return "URLhaus";
    }

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();
        
        return params;
    }
    
    private String apiBase = "https://urlhaus-api.abuse.ch";
    
    private JSONObject query(String url, String body, final PluginInteraction interaction)
    {
        JSONObject result = null;
        ProxySelector ps = ConstellationHttpProxySelector.getDefault();
        try {
            List<Proxy> proxies = ps.select(new URI(apiBase));
            for (Proxy proxy : proxies) {
                HttpClientBuilder clientBuilder = HttpClients.custom();
                if (proxy.type() != Proxy.Type.DIRECT) {
                    String h = proxy.address().toString();
                    String addr = null;
                    Integer port = null;
                    if (h.contains(":")) {
                        addr = h.split(":")[0];
                        addr = addr.split("/")[0];
                        port = Integer.parseInt(h.split(":")[1]);
                    } else {
                        addr = h;
                    }
                    if (port != null) {
                        clientBuilder.setProxy(new HttpHost(addr, port));
                    } else {
                        clientBuilder.setProxy(new HttpHost(addr));
                    }
                }
                CloseableHttpClient client = clientBuilder.build();

                HttpPost post = new HttpPost(url);
                post.setEntity(new StringEntity(body));
                post.setHeader("Content-Type", "application/x-www-form-urlencoded");

                CloseableHttpResponse resp;
                try {
                    resp = client.execute(post);
                    if (resp.getStatusLine().getStatusCode() == 200) {
                        JSONParser parser = new JSONParser();
                        result = (JSONObject)parser.parse(EntityUtils.toString(resp.getEntity()));
                    }
                    else
                    {
                        interaction.notify(PluginNotificationLevel.FATAL, "Failed to query webservice. " + resp.getStatusLine().getReasonPhrase());
                    }
                } catch (IOException ex) {
                    interaction.notify(PluginNotificationLevel.FATAL, "Failed to query webservice. " + ex.getMessage());
                } catch (ParseException ex) {
                    interaction.notify(PluginNotificationLevel.FATAL, "Failed to parse the web service results. " + ex.getMessage());
                }
            }
        } catch (URISyntaxException ex) {
            interaction.notify(PluginNotificationLevel.FATAL, "Failed to query webservice. " + ex.getReason());
        } catch (UnsupportedEncodingException ex) {
            interaction.notify(PluginNotificationLevel.FATAL, "Failed to query webservice. " + ex.getMessage());
        }
        return result;
    }

    private JSONObject queryHost(String host, final PluginInteraction interaction)
    {
        JSONObject result = null;
        String url = String.format("%s/v1/host/", apiBase);
        String body = null;
        body = String.format("host=%s", host); 
        result = query(url, body, interaction);
        return result;
    }

    private JSONObject queryPayload(String hash, String type, final PluginInteraction interaction)
    {
        JSONObject result = null;
        String url = String.format("%s/v1/payload/", apiBase);
        String body = null;
        if (type.equals(AnalyticConcept.VertexType.MD5.toString()))
        {
            body = String.format("md5_hash=%s", hash);
        }
        else
        {
            body= String.format("sha256_hash=%s", hash);
        }
        result = query(url, body, interaction);
        return result;
    }
    
    private JSONObject querySignature(String signature, final PluginInteraction interaction)
    {
        JSONObject result = null;
        String url = String.format("%s/v1/signature/", apiBase);
        String body = null;

        body = String.format("signature=%s", signature);
        result = query(url, body, interaction);
        return result;
    }

    @Override
    protected RecordStore query(final RecordStore query, final PluginInteraction interaction, final PluginParameters parameters) throws PluginException {

        final RecordStore results = new GraphRecordStore();
        if (query.size() == 0) {
            return results;
        }

        query.reset();
        int i= 0;
        try
        {
            while (query.next()) {
                i++;

                String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
                String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);
                interaction.setProgress(i, query.size(), "Querying on " + identifier, true);
                if (type.equals(AnalyticConcept.VertexType.HOST_NAME.toString()) ||
                    type.equals(AnalyticConcept.VertexType.IPV4.toString())) 
                {
                    JSONObject res = queryHost(identifier, interaction);
                    if (res != null)
                    {
                        String status = (String)res.get("query_status");
                        if (status.equalsIgnoreCase("ok"))
                        {
                            String firstSeen = ((String)res.get("firstseen")).replace(" UTC", "");
                            int urlCount = Integer.parseInt((String)res.get("url_count"));
                            JSONObject blacklists = (JSONObject)res.get("blacklists");
                            String spamhaus = (String)blacklists.get("spamhaus_dbl");
                            String surbl = (String)blacklists.get("surbl");

                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                            results.set(GraphRecordStoreUtilities.SOURCE + URLHausConcept.VertexAttribute.HAS_ENTRY, true);
                            results.set(GraphRecordStoreUtilities.SOURCE + URLHausConcept.VertexAttribute.SPAMHAUS_ENTRY, spamhaus);
                            results.set(GraphRecordStoreUtilities.SOURCE + URLHausConcept.VertexAttribute.SURBL_ENTRY, surbl);
                            results.set(GraphRecordStoreUtilities.SOURCE + URLHausConcept.VertexAttribute.URL_COUNT, urlCount);
                            results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.FIRST_SEEN, TemporalFormatting.completeZonedDateTimeString(firstSeen));
                        }
                        else if (status.equalsIgnoreCase("invalid_host") || status.equalsIgnoreCase("no_results"))
                        {
                           results.set(GraphRecordStoreUtilities.SOURCE + URLHausConcept.VertexAttribute.HAS_ENTRY, false); 
                        }
                    }
                }
                else if (type.equals(AnalyticConcept.VertexType.MD5.toString()) ||
                    type.equals(AnalyticConcept.VertexType.SHA256.toString())) 
                {
                    JSONObject res = queryPayload(identifier, type, interaction);
                    if (res != null)
                    {
                        String status = (String)res.get("query_status");
                        if (status.equalsIgnoreCase("ok"))
                        {
                            String firstSeen = ((String)res.get("firstseen")).replace(" UTC", "");
                            String lastSeen = ((String)res.get("lastseen")).replace(" UTC", "");
                            String md5 = (String)res.get("md5_hash");
                            String sha256 = (String)res.get("sha256_hash");
                            String fileType = (String)res.get("file_type");
                            String fileSize = (String)res.get("file_size");
                            String signature = (String)res.get("signature");
                            String urlCount = (String)res.get("url_count");
                            String impHash = (String)res.get("imphash");
                            String ssdeep = (String)res.get("ssdeep");

                            if (!md5.equalsIgnoreCase(identifier))
                            {
                                results.add();
                                results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                                results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                                results.set(GraphRecordStoreUtilities.SOURCE + URLHausConcept.VertexAttribute.HAS_ENTRY, true);
                                results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                                results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
                                results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, AnalyticConcept.TransactionType.SIMILARITY);
                            }

                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
                            results.set(GraphRecordStoreUtilities.SOURCE + URLHausConcept.VertexAttribute.HAS_ENTRY, true);
                            results.set(GraphRecordStoreUtilities.SOURCE + URLHausConcept.VertexAttribute.URL_COUNT, urlCount);
                            results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.SHA256, sha256);
                            results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.SSDEEP, ssdeep);
                            results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.IMPHASH, impHash);
                            results.set(GraphRecordStoreUtilities.SOURCE + CyberConcept.VertexAttribute.SIZE, fileSize);
                            results.set(GraphRecordStoreUtilities.SOURCE + "File Type", fileType);
                            results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.FIRST_SEEN, TemporalFormatting.completeZonedDateTimeString(firstSeen));
                            results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.LAST_SEEN, TemporalFormatting.completeZonedDateTimeString(lastSeen));

                            if (signature != null)
                            {
                                results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, signature);
                                results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.CODE_FAMILY);
                                results.set(GraphRecordStoreUtilities.DESTINATION + CyberConcept.VertexAttribute.FAMILY_TYPE, "malware");
                            }

                            JSONArray urls = (JSONArray)res.get("urls");

                            if (urls != null)
                            {
                                for (Object u : urls)
                                {
                                    JSONObject url = (JSONObject)u;

                                    try {
                                        URL a = new URL((String)url.get("url"));
                                        String host = a.getHost();
                                        results.add();
                                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, host);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + URLHausConcept.VertexAttribute.HAS_ENTRY, true); 
                                        results.set(GraphRecordStoreUtilities.TRANSACTION + "URL", (String)url.get("url")); 
                                        results.set(GraphRecordStoreUtilities.TRANSACTION + "Filename", (String)url.get("filename"));
                                    } catch (MalformedURLException ex) {
                                        Exceptions.printStackTrace(ex);
                                    }
                                }
                            }
                        }
                        else if (status.equalsIgnoreCase("invalid_host") || status.equalsIgnoreCase("no_results"))
                        {
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                            results.set(GraphRecordStoreUtilities.SOURCE + URLHausConcept.VertexAttribute.HAS_ENTRY, false); 
                        }
                    }
                }
                else if (type.equals(CyberConcept.VertexType.CODE_FAMILY.toString())) 
                {
                    JSONObject res = querySignature(identifier, interaction);
                    if (res != null)
                    {
                        String status = (String)res.get("query_status");
                        if (status.equalsIgnoreCase("ok"))
                        {

                            String firstSeen = ((String)res.get("firstseen")).replace(" UTC", "");
                            String lastSeen = ((String)res.get("lastseen")).replace(" UTC", "");


                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.CODE_FAMILY);

                            results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.FIRST_SEEN, TemporalFormatting.completeZonedDateTimeString(firstSeen));
                            results.set(GraphRecordStoreUtilities.SOURCE + TemporalConcept.VertexAttribute.LAST_SEEN, TemporalFormatting.completeZonedDateTimeString(lastSeen));

                            JSONArray urls = (JSONArray)res.get("urls");

                            if (urls != null)
                            {
                                for (Object u : urls)
                                {
                                    JSONObject url = (JSONObject)u;

                                    try {
                                        URL a = new URL((String)url.get("url"));
                                        String host = a.getHost();

                                        String md5 = (String)url.get("md5_hash");
                                        String sha256 = (String)url.get("sha256_hash");
                                        String ssdeep = (String)url.get("ssdeep");
                                        String impHash = (String)url.get("imphash");
                                        String fileType = (String)url.get("file_type");
                                        String fileSize = (String)url.get("file_size");
                                        String ufirstSeen = ((String)url.get("firstseen")).replace(" UTC", "");
                                        String ulastSeen = ((String)url.get("lastseen")).replace(" UTC", "");

                                        results.add();
                                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.CODE_FAMILY);

                                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + URLHausConcept.VertexAttribute.HAS_ENTRY, true); 
                                        results.set(GraphRecordStoreUtilities.DESTINATION + CyberConcept.VertexAttribute.SHA256, sha256);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + CyberConcept.VertexAttribute.SSDEEP, ssdeep);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + CyberConcept.VertexAttribute.IMPHASH, impHash);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + CyberConcept.VertexAttribute.SIZE, fileSize);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + "File Type", fileType);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + TemporalConcept.VertexAttribute.FIRST_SEEN, TemporalFormatting.completeZonedDateTimeString(ufirstSeen));
                                        results.set(GraphRecordStoreUtilities.DESTINATION + TemporalConcept.VertexAttribute.LAST_SEEN, TemporalFormatting.completeZonedDateTimeString(ulastSeen));

                                        results.add();
                                        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, md5);
                                        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.MD5);

                                        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, host);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
                                        results.set(GraphRecordStoreUtilities.DESTINATION + URLHausConcept.VertexAttribute.HAS_ENTRY, true); 
                                        results.set(GraphRecordStoreUtilities.TRANSACTION + "URL", (String)url.get("url")); 
                                        results.set(GraphRecordStoreUtilities.TRANSACTION + "Filename", (String)url.get("filename"));

                                    } catch (MalformedURLException ex) {
                                        Exceptions.printStackTrace(ex);
                                    }
                                }
                            }
                        }
                        else if (status.equalsIgnoreCase("invalid_host") || status.equalsIgnoreCase("no_results"))
                        {
                            results.add();
                            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, identifier);
                            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                            results.set(GraphRecordStoreUtilities.SOURCE + URLHausConcept.VertexAttribute.HAS_ENTRY, false); 
                        }
                    }
                }
            }
        } catch (InterruptedException ex) {
            Exceptions.printStackTrace(ex);
        }

        return results;
    }

}
