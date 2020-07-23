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
package au.gov.asd.acsc.constellation.dataaccess.cyber.plugins.shodan;

import au.gov.asd.acsc.constellation.preferences.ACSCPreferenceKeys;
import au.gov.asd.acsc.constellation.schema.cyberschema.concept.CyberConcept;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.ContentConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.SpatialConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.TemporalConcept;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.Plugin;
import au.gov.asd.tac.constellation.plugins.PluginException;
import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.PluginNotificationLevel;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameter;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.plugins.parameters.types.BooleanParameterType;
import au.gov.asd.tac.constellation.plugins.parameters.types.StringParameterType;
import au.gov.asd.tac.constellation.plugins.parameters.types.StringParameterValue;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPlugin;
import au.gov.asd.tac.constellation.views.dataaccess.DataAccessPluginCoreType;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import com.google.common.net.UrlEscapers;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
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
@Messages("ShodanPlugin=Shodan")
public class ShodanPlugin extends RecordStoreQueryPlugin implements DataAccessPlugin {

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
        return "Shodan";
    }
    
    public static final String ADHOC_PARAMETER = PluginParameter.buildId(ShodanPlugin.class, "adhoc");
    public static final String SHOW_TAGS_PARAMETER = PluginParameter.buildId(ShodanPlugin.class, "showTags");

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();
        final PluginParameter<StringParameterValue> q = StringParameterType.build(ADHOC_PARAMETER);
        q.setName("Query");
        params.addParameter(q);
        
        final PluginParameter<BooleanParameterType.BooleanParameterValue> showTags = BooleanParameterType.build(SHOW_TAGS_PARAMETER);
        showTags.setName("Show Tags");
        showTags.setBooleanValue(false);
        params.addParameter(showTags);
        
        return params;
    }
    
    private void drawSSLCert(JSONObject sslCert, String end, RecordStore results)
    {
        JSONObject fingerprint = sslCert.getJSONObject("fingerprint");
        results.set(end + VisualConcept.VertexAttribute.IDENTIFIER, sslCert.get("serial") );
        results.set(end + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.CERTIFICATE);
        results.set(end + CyberConcept.VertexAttribute.SHA256, fingerprint.get("sha256") );
        results.set(end + CyberConcept.VertexAttribute.SHA1, fingerprint.get("sha1") );
        results.set(end + "Serial", sslCert.get("serial") );
        results.set(end + "Expires", TemporalFormatting.parseAsZonedDateTime(sslCert.getString("expires"), DateTimeFormatter.ofPattern("yyyyMMddHHmmssX"), null)  );
        results.set(end + "Issued", TemporalFormatting.parseAsZonedDateTime(sslCert.getString("issued"), DateTimeFormatter.ofPattern("yyyyMMddHHmmssX"), null)  );
        if (sslCert.has("issuer"))
        {
            JSONObject issuer = sslCert.getJSONObject("issuer");
            if (issuer.has("C"))
            {
                results.set(end + "Issuer C", issuer.get("C") );
            }
            if (issuer.has("CN"))
            {
                results.set(end + "Issuer CN", issuer.get("CN") );
            }
            if (issuer.has("L"))
            {
                results.set(end + "Issuer L", issuer.get("L") );
            }
            if (issuer.has("O"))
            {
                results.set(end + "Issuer O", issuer.get("O") );
            }
            if (issuer.has("OU"))
            {
                results.set(end + "Issuer OU", issuer.get("OU") );
            }
            if (issuer.has("ST"))
            {
                results.set(end + "Issuer ST", issuer.get("ST") );
            }
        }
        if (sslCert.has("subject"))
        {
            JSONObject subject = sslCert.getJSONObject("subject");
            if (subject.has("C"))
            {
                results.set(end + "Subject C", subject.get("C") );
            }
            if (subject.has("CN"))
            {
                results.set(end + "Subject CN", subject.get("CN") );
            }
            if (subject.has("L"))
            {
                results.set(end + "Subject L", subject.get("L") );
            }
            if (subject.has("O"))
            {
                results.set(end + "Subject O", subject.get("O") );
            }
            if (subject.has("OU"))
            {
                results.set(end + "Subject OU", subject.get("OU") );
            }
            if (subject.has("ST"))
            {
                results.set(end + "Subject ST", subject.get("ST") );
            }
        }
    }
    
    private void drawTags(JSONObject b, String ip, String type, RecordStore results)
    {
        JSONArray tags = b.getJSONArray("tags");
        for (Object t : tags)
        {
            results.add();
            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, (String)t);
            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, "Tag");
        }
    }
    
    private void drawLocation(JSONObject b, String ip, String type, RecordStore results)
    {
        results.add();
        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

        JSONObject location = b.getJSONObject("location");
        if (location.has("country_name") && location.get("country_name") != null)
        {
            results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.COUNTRY, location.get("country_name"));
        }
        if (location.has("city") && location.get("city") != null)
        {
            results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.CITY, location.get("city"));
        }
        if (location.has("latitude") && location.get("latitude") != null)
        {
            results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LATITUDE, location.get("latitude"));
        }
        if (location.has("longitude") && location.get("longitude") != null)
        {
            results.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LONGITUDE, location.get("longitude"));
        }
        if (location.has("postal_code") && location.get("postal_code") != null)
        {
            results.set(GraphRecordStoreUtilities.SOURCE + "Postal Code", location.get("postal_code"));
        }
        if (location.has("region_code") && location.get("region_code") != null)
        {
            results.set(GraphRecordStoreUtilities.SOURCE + "Region", location.get("region_code"));
        }
    }
    
    private void drawHttp(JSONObject b, String ip, String type, RecordStore results)
    {
        JSONObject shodan = b.getJSONObject("_shodan");
        JSONObject http = b.getJSONObject("http");
        results.add();
        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, http.getString("host"));
        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);

        results.set(GraphRecordStoreUtilities.TRANSACTION + "Headers", b.get("data"));
        results.set(GraphRecordStoreUtilities.TRANSACTION + ContentConcept.VertexAttribute.CONTENT, http.get("html"));
        results.set(GraphRecordStoreUtilities.TRANSACTION + ContentConcept.VertexAttribute.TITLE, http.get("title"));
        results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, TemporalFormatting.completeZonedDateTimeString((String)b.get("timestamp")));
        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, shodan.getString("module"));
        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.SOURCE, "Shodan");
        if (http.has("location"))
        {
            results.set(GraphRecordStoreUtilities.TRANSACTION + "Location", http.getString("location"));
        }
    }
    
    private void drawSsl(JSONObject b, String ip, String type, RecordStore results)
    {
        JSONObject shodan = b.getJSONObject("_shodan");
        JSONObject ssl = b.getJSONObject("ssl");
        if (ssl.has("cert"))
        {
            JSONObject cert = ssl.getJSONObject("cert");
            results.add();
            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
            
            drawSSLCert(cert, GraphRecordStoreUtilities.DESTINATION, results);

            results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, TemporalFormatting.completeZonedDateTimeString((String)b.get("timestamp")));
            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, shodan.getString("module"));
            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.SOURCE, "Shodan");            
        }
    }
    
    private void drawDns(JSONObject b, String ip, String type, RecordStore results)
    {
        JSONObject dns = b.getJSONObject("dns");
        results.add();
        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
        if (dns.has("resolver_hostname") && dns.get("resolver_hostname") != null)
        {
            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, dns.get("resolver_hostname"));
            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.HOST_NAME);
        }
    }
    
    private void drawFtp(JSONObject b, String ip, String type, RecordStore results)
    {
        JSONObject ftp = b.getJSONObject("ftp");
        
        JSONObject shodan = b.getJSONObject("_shodan");

        String module = shodan.getString("module");
        String version = "";
        if (b.has("version"))
        {
            version = b.getString("version");
        }
        String product = "";
        if (b.has("product"))
        {
            product = b.getString("product");
        }
        String port = "";
        if (b.has("port"))
        {
            port = Integer.toString(b.getInt("port"));
        }
        String transport = "";
        if (b.has("transport"))
        {
            transport = b.getString("transport");
        }

        String serviceName = String.format("%s-%s-%s %s %s", port, transport, module, product, version ).trim();

        results.add();
        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, serviceName);
        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.SERVICE);
        results.set(GraphRecordStoreUtilities.DESTINATION + "Product", product);
        results.set(GraphRecordStoreUtilities.DESTINATION + "Version", version);
        results.set(GraphRecordStoreUtilities.DESTINATION + "Module", module);
        results.set(GraphRecordStoreUtilities.DESTINATION + "JSON", b.toString(4));
        results.set(GraphRecordStoreUtilities.DESTINATION + "Port", port);
        results.set(GraphRecordStoreUtilities.DESTINATION + "Transport", transport);

        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, module);
        results.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.VertexAttribute.IDENTIFIER, shodan.get("id")+"-"+serviceName);
        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.SOURCE, "Shodan");
        if (ftp.has("anonymous"))
        {
            results.set(GraphRecordStoreUtilities.TRANSACTION + "Anonymous?", ftp.get("anonymous"));
        }
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Data", b.getString("data"));
        results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, TemporalFormatting.completeZonedDateTimeString((String)b.get("timestamp")));
            
    }
    
    private void drawNtp(JSONObject b, String ip, String type, RecordStore results)
    {
        JSONObject ntp = b.getJSONObject("ntp");
        
        JSONObject shodan = b.getJSONObject("_shodan");

        String module = shodan.getString("module");
        String version = "";
        if (b.has("version"))
        {
            version = b.getString("version");
        }
        String product = "";
        if (b.has("product"))
        {
            product = b.getString("product");
        }
        String port = "";
        if (b.has("port"))
        {
            port = Integer.toString(b.getInt("port"));
        }
        String transport = "";
        if (b.has("transport"))
        {
            transport = b.getString("transport");
        }

        String serviceName = String.format("%s-%s-%s %s %s", port, transport, module, product, version ).trim();

        results.add();
        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, serviceName);
        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.SERVICE);
        results.set(GraphRecordStoreUtilities.DESTINATION + "Product", product);
        results.set(GraphRecordStoreUtilities.DESTINATION + "Version", version);
        results.set(GraphRecordStoreUtilities.DESTINATION + "Module", module);
        results.set(GraphRecordStoreUtilities.DESTINATION + "JSON", b.toString(4));
        results.set(GraphRecordStoreUtilities.DESTINATION + "Port", port);
        results.set(GraphRecordStoreUtilities.DESTINATION + "Transport", transport);

        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, module);
        results.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.VertexAttribute.IDENTIFIER, shodan.get("id")+"-"+serviceName);
        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.SOURCE, "Shodan");
        
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Data", b.getString("data"));
        results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, TemporalFormatting.completeZonedDateTimeString((String)b.get("timestamp")));
            
    }
    
    private void drawSsh(JSONObject b, String ip, String type, String end, String endType, RecordStore results)
    {
        JSONObject ssh = (JSONObject)b.get("ssh");
        
        results.add();
        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
        
        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, end);
        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, endType);
        
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Cipher", ssh.get("cipher"));
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Hassh", ssh.get("hassh"));
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Key", ssh.get("key"));
        results.set(GraphRecordStoreUtilities.TRANSACTION + "SSH Type", ssh.get("type"));  
    }
    
    private void drawResults(JSONObject b, boolean showTags, RecordStore results)
    {
        String ip = b.getString("ip_str");
        String type = "";
        if (ip != null)
        {
            type = AnalyticConcept.VertexType.IP_ADDRESS.getName();
            if (ip.contains("."))
            {
                type = AnalyticConcept.VertexType.IPV4.getName();
            }
            else if (ip.contains(":"))
            {
                type = AnalyticConcept.VertexType.IPV6.getName();
            }
        }
        
        if (b.has("hostnames") && b.get("hostnames") != null && b.getJSONArray("hostnames").length() > 0)
        {
            for (Object o : b.getJSONArray("hostnames"))
            {
                drawResults(b, showTags, ip, type, (String)o, AnalyticConcept.VertexType.HOST_NAME.getName(), results);
            }
        }
        else 
        {
            results.add();
            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
            if (b.has("isp"))
            {
                results.set(GraphRecordStoreUtilities.SOURCE + "ISP", b.get("isp"));
            }
            if (b.has("org"))
            {
                results.set(GraphRecordStoreUtilities.SOURCE + "Organisation", b.get("org"));
            }
            
            JSONObject shodan = b.getJSONObject("_shodan");

            String module = shodan.getString("module");
            String version = "";
            if (b.has("version"))
            {
                version = b.getString("version");
            }
            String product = "";
            if (b.has("product"))
            {
                product = b.getString("product");
            }
            String port = "";
            if (b.has("port"))
            {
                port = Integer.toString(b.getInt("port"));
            }
            String transport = "";
            if (b.has("transport"))
            {
                transport = b.getString("transport");
            }

            String serviceName = String.format("%s-%s-%s %s %s", port, transport, module, product, version ).trim();

            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, serviceName);
            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.SERVICE);
            results.set(GraphRecordStoreUtilities.DESTINATION + "Product", product);
            results.set(GraphRecordStoreUtilities.DESTINATION + "Version", version);
            results.set(GraphRecordStoreUtilities.DESTINATION + "Module", module);
            results.set(GraphRecordStoreUtilities.DESTINATION + "JSON", b.toString(4));
            results.set(GraphRecordStoreUtilities.DESTINATION + "Port", port);
            results.set(GraphRecordStoreUtilities.DESTINATION + "Transport", transport);

            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, module);
            results.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.VertexAttribute.IDENTIFIER, shodan.get("id")+"-"+serviceName);
            results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.SOURCE, "Shodan");
            results.set(GraphRecordStoreUtilities.TRANSACTION + "Data", b.getString("data"));
            results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, TemporalFormatting.completeZonedDateTimeString((String)b.get("timestamp")));
            
            drawResults(b, showTags, ip, type, serviceName, CyberConcept.VertexType.SERVICE.getName(), results);
        }
    }
    
    private void drawResults(JSONObject b, boolean showTags, String start, String startType, String end, String endType, RecordStore results)
    {
        results.add();
        results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, start);
        results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, startType);
        if (b.has("isp"))
        {
            results.set(GraphRecordStoreUtilities.SOURCE + "ISP", b.get("isp"));
        }
        if (b.has("org"))
        {
            results.set(GraphRecordStoreUtilities.SOURCE + "Organisation", b.get("org"));
        }
        
        JSONObject shodan = b.getJSONObject("_shodan");
        
        String module = shodan.getString("module");
        String version = "";
        if (b.has("version"))
        {
            version = b.getString("version");
        }
        String product = "";
        if (b.has("product"))
        {
            product = b.getString("product");
        }
        String port = "";
        if (b.has("port"))
        {
            port = Integer.toString(b.getInt("port"));
        }
        String transport = "";
        if (b.has("transport"))
        {
            transport = b.getString("transport");
        }
        results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, end);
        results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, endType);
        
        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, module);
        results.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.VertexAttribute.IDENTIFIER, shodan.get("id") + "-" + end);
        results.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.VertexAttribute.SOURCE, "Shodan");
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Data", b.getString("data"));
        results.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.TransactionAttribute.DATETIME, TemporalFormatting.completeZonedDateTimeString((String)b.get("timestamp")));
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Product", product);
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Version", version);
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Module", module);
        results.set(GraphRecordStoreUtilities.TRANSACTION + "JSON", b.toString(4));
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Port", port);
        results.set(GraphRecordStoreUtilities.TRANSACTION + "Transport", transport);

        for (String key : b.keySet())
        {
            List<String> ignores = Arrays.asList("_shodan", "timestamp","data","hash","transport","asn","ip_str","ip","isp",
                    "domains","cpe","port","org","product","version","os","info","link","hostnames","opts", "tags");
            if ( ignores.contains(key))
            {
                // do nothing
            }
            else if (key.equalsIgnoreCase("tags") && showTags)
            {
                drawTags(b, start, startType, results);     
            }
            else if (key.equalsIgnoreCase("location"))
            {
                drawLocation(b, start, startType, results);
            }
            else if (key.equalsIgnoreCase("vulns"))
            {
                drawVulnerabilities(b, start, startType, results);  
            }
            else if (key.equalsIgnoreCase("http"))
            {
                drawHttp(b, start, startType, results);  
            }
            else if (key.equalsIgnoreCase("ssl"))
            {
                drawSsl(b, end, endType, results);
            }
            else if (key.equalsIgnoreCase("dns"))
            {
                drawDns(b, start, startType, results);
            }
            else if (key.equalsIgnoreCase("ssh"))
            {
                drawSsh(b, start, startType, end, endType, results);         
            }
            else if (key.equalsIgnoreCase("ftp"))
            {
                drawFtp(b, start, startType, results);
            }
            else if (key.equalsIgnoreCase("ntp"))
            {
                drawNtp(b, start, startType, results);
            }
            else 
            {
                
            }
        }
    }
    
    private void drawVulnerabilities(JSONObject b, String ip, String type, RecordStore results)
    {
       JSONObject vulns = b.getJSONObject("vulns");
       for (Object k : vulns.keySet())
       {
            String cveName = (String)k;
            JSONObject cve = vulns.getJSONObject(cveName);
           
            results.add();
            results.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, ip);
            results.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

            results.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, cveName);
            results.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, CyberConcept.VertexType.CVE);
            
            JSONArray refs = cve.getJSONArray("references");
            ArrayList<String> rs = new ArrayList<>();
            for (Object a : refs)
            {
                rs.add((String)a);
            }
            
            results.set(GraphRecordStoreUtilities.DESTINATION + "References", String.join("\n", rs));
            results.set(GraphRecordStoreUtilities.DESTINATION + "Summary", cve.get("summary"));
            results.set(GraphRecordStoreUtilities.DESTINATION + "CVSS", cve.get("cvss"));
            results.set(GraphRecordStoreUtilities.DESTINATION + "Verified", cve.get("verified"));
       }
    }
    
    private boolean runQuery(String query, boolean showTags, ShodanClient client, RecordStore results, PluginInteraction interaction)
    {
        Integer resultCount = client.searchCount(query, interaction);

        if (resultCount != null && resultCount > 0 )
        {
            JSONObject res = client.search(query, interaction);
            if (res != null)
            {
                JSONArray matches = res.getJSONArray("matches");
                for (Object o : matches)
                {
                    JSONObject p = (JSONObject)o;
                    drawResults(p, showTags, results);
                } 
            }
            else
            {
                return false;
            }
        }
        return true;
    }

    @Override
    protected RecordStore query(final RecordStore query, final PluginInteraction interaction, final PluginParameters parameters) throws PluginException {

        final RecordStore results = new GraphRecordStore();

        String APIKey = null;
        
        Preferences prefs = NbPreferences.forModule(ACSCPreferenceKeys.class);

        APIKey = prefs.get(ACSCPreferenceKeys.SHODAN_API_KEY, "");
        if (APIKey == null || APIKey.isEmpty())
        {
            interaction.notify(PluginNotificationLevel.FATAL, "The API key has not been set.\nPlease update these at Setup > Options > CONSTELLATION > ACSC > Shodan");
            return results;
        }
        
        
        ShodanClient client = new ShodanClient(APIKey);
        
        
        final Map<String, PluginParameter<?>> params = parameters.getParameters();
        String q = params.get(ADHOC_PARAMETER).getStringValue();
        boolean showTags = params.get(SHOW_TAGS_PARAMETER).getBooleanValue();
        
        if (q != null && !q.isEmpty())
        {
            runQuery(UrlEscapers.urlFormParameterEscaper().escape(q), showTags, client, results, interaction);
        }
        else
        {
            if (query.size() == 0) {
                return results;
            }

            query.reset();
            while (query.next()) {
                String identifier = query.get(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER);
                String type = query.get(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE);
                
                String search = null;
                if (type.equals(AnalyticConcept.VertexType.IPV4.toString())) 
                {
                     search = String.format("ip:%s",identifier);
                }
                else if (type.equals(AnalyticConcept.VertexType.HOST_NAME.toString())) 
                {
                    search = String.format("hostname:%s",identifier);
                }
                else if (type.equals(CyberConcept.VertexType.CERTIFICATE.toString())) 
                {
                    search = String.format("ssl.cert.serial:%s",identifier);
                }
                
                if (search != null)
                {
                    if (!runQuery(search, showTags, client, results, interaction))
                    {
                        break;
                    }
                }
            }
        }

        return results;
    }

}
