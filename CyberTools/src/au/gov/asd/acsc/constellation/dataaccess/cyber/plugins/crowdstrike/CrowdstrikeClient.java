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

import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.PluginNotificationLevel;
import au.gov.asd.tac.constellation.security.proxy.ConstellationHttpProxySelector;
import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.python.google.common.net.UrlEscapers;

public class CrowdstrikeClient 
{
    String secret = null;
    String username = null;
    String apiBase = "https://intelapi.crowdstrike.com";
    
    HashMap<String, String> cache = new HashMap<>();
    
    CloseableHttpClient client = null;
    HttpClientContext context = HttpClientContext.create();
    
    public JSONArray searchIPAddress(String query, PluginInteraction interaction)
    {
        String res = getQuery(String.format("%s/indicator/v2/search/indicator?equal=%s&perPage=10000", apiBase, UrlEscapers.urlFormParameterEscaper().escape(query)), interaction);
        if (res != null)
        {
            return new JSONArray(res);
        }
        return null;
    }
        
    public JSONObject getActor(String query, PluginInteraction interaction)
    {
        JSONObject s = new JSONObject(getQuery(String.format("%s/actors/queries/actors/v1?name=%s&perPage=10000", apiBase, UrlEscapers.urlFormParameterEscaper().escape(query)), interaction));
        ArrayList<String> ids = new ArrayList<>();
        for (Object id : s.getJSONArray("resources"))
        {
            ids.add("ids=" + id);
        }
        if (ids.isEmpty())
        {
            return null;
        }
        else
        {
            return new JSONObject(getQuery(String.format("%s/actors/entities/actors/v1?%s&fields=__full__&perPage=10000", apiBase, String.join("&", ids)), interaction));
        }
        
    }
    
    public JSONArray searchDomain(String query, PluginInteraction interaction)
    {
        String res = getQuery(String.format("%s/indicator/v2/search/indicator?equal=%s&perPage=10000", apiBase, UrlEscapers.urlFormParameterEscaper().escape(query)), interaction);
        if (res != null)
        {
            return new JSONArray(res);
        }
        return null;
    }
    
    public JSONArray searchEmailAddress(String query, PluginInteraction interaction)
    {
        String res = getQuery(String.format("%s/indicator/v2/search/indicator?equal=%s&perPage=10000", apiBase, UrlEscapers.urlFormParameterEscaper().escape(query)), interaction);
        if (res != null)
        {
            return new JSONArray(res);
        }
        return null;
    }
    
    public JSONArray searchUrl(String query, PluginInteraction interaction)
    {
        String res = getQuery(String.format("%s/indicator/v2/search/indicator?equal=%s&perPage=10000", apiBase, UrlEscapers.urlFormParameterEscaper().escape(query)), interaction);
        if (res != null)
        {
            return new JSONArray(res);
        }
        return null;
    }
    
    public JSONArray searchGeneric(String query, PluginInteraction interaction)
    {
        String res = getQuery(String.format("%s/indicator/v2/search/indicator?equal=%s&perPage=10000", apiBase, UrlEscapers.urlFormParameterEscaper().escape(query)), interaction);
        if (res != null)
        {
            return new JSONArray(res);
        }
        return null;
    }
    
    public JSONArray searchActor(String query, PluginInteraction interaction)
    {
        String res = getQuery(String.format("%s/indicator/v2/search/actor?equal=%s&perPage=10000", apiBase, UrlEscapers.urlFormParameterEscaper().escape(query.replace(" ", "").toUpperCase())), interaction);
        if (res != null)
        {
            return new JSONArray(res);
        }
        return null;
        
    }
    
    public JSONArray searchHash(String query, PluginInteraction interaction)
    {
        String res = getQuery(String.format("%s/indicator/v2/search/indicator?equal=%s&perPage=10000", apiBase, UrlEscapers.urlFormParameterEscaper().escape(query)), interaction);
        if (res != null)
        {
            return new JSONArray(res);
        }
        return null;
    }
    
    public JSONObject searchReportName(String query, PluginInteraction interaction)
    {
        JSONObject s = new JSONObject(getQuery(String.format("%s/reports/queries/reports/v1?name=%s&perPage=10000", apiBase, UrlEscapers.urlFormParameterEscaper().escape(query)), interaction));
        
        String ids = "";
        for (Object id : s.getJSONArray("resources"))
        {
            ids += "ids=" + id;
        }
        if (ids.isEmpty())
        {
            return null;
        }
        else
        {
            return new JSONObject(getQuery(String.format("%s/reports/entities/reports/v1?%s&perPage=10000", apiBase, ids), interaction));
        }
 
    }
    
    private String getQuery(String query, PluginInteraction interaction)
    {
        if (cache.containsKey(query))
        {
            return cache.get(query);
        }
        String res = null;
        int retry = 0;
        while (true && retry < 3)
        {
            String out = getObject(query, interaction);
            if (out != null)
            {
                cache.put(query, out);
                return out;
            }
            else
            {
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException ex) {
                    return null;
                }
                retry++;
            }
               
        }
        return res;
        
    }
    
    public CloseableHttpClient getClient()
    {
        return client;
    }
    
    private String getObject(String query, PluginInteraction interaction) 
    {
        String result = null;
        
        if (client == null)
        {
            try {
                ProxySelector sel = ConstellationHttpProxySelector.getDefault();
                List<Proxy> proxies = sel.select(new URI(query));
                for (Proxy proxy : proxies) {
                    HttpClientBuilder clientBuilder = HttpClients.custom();
                    RequestConfig gc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setAuthenticationEnabled(true).build();
                    clientBuilder.setConnectionManagerShared(true);
                    
                    clientBuilder.setDefaultCookieStore(new BasicCookieStore());
                    clientBuilder.setDefaultRequestConfig(gc);
                    ArrayList<Header> headers = new ArrayList<>();
                    headers.add(new BasicHeader("X-CSIX-CUSTID", username));
                    headers.add(new BasicHeader("X-CSIX-CUSTKEY", secret));
                    clientBuilder.setDefaultHeaders(headers);
                    

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
                    client = clientBuilder.build();
                    HttpGet get = new HttpGet(query);

                    get.addHeader("Accept", "application/json");

                    try (CloseableHttpResponse resp = client.execute(get, context)){
                        if (resp.getStatusLine().getStatusCode() == 200) {
                            String answer = EntityUtils.toString(resp.getEntity());
                            EntityUtils.consume(resp.getEntity());
                            result = answer;
                        }
                        else if (resp.getStatusLine().getStatusCode() == 401) { // unauthorised
                            String answer = EntityUtils.toString(resp.getEntity());
                        }
                        else {
                            //unhandled
                            //System.out.println(resp.getStatusLine().getReasonPhrase());
                        }

                    } catch (IOException ex) {
                        ex.printStackTrace();
                        if (interaction != null) {
                            interaction.notify(PluginNotificationLevel.FATAL, "Failed to query the CrowdStrike web service " + ex.getMessage());
                        }
                    }
                    catch (org.apache.http.ParseException ex) {
                        ex.printStackTrace();
                    }
                    break;
                }

            } catch (URISyntaxException ex) {
                ex.printStackTrace();
            }
        }
        else
        {
            HttpGet get = new HttpGet(query);

            get.addHeader("Accept", "application/json");
            try (CloseableHttpResponse resp = client.execute(get, context)){

                if (resp.getStatusLine().getStatusCode() == 200) {
                    String answer = EntityUtils.toString(resp.getEntity());
                    EntityUtils.consume(resp.getEntity());
                    result = answer;
                }
                else if (resp.getStatusLine().getStatusCode() == 401) { // unauthorised
                    String answer = EntityUtils.toString(resp.getEntity());
                }
                else {
                    // unhandled
                    // System.out.println(resp.getStatusLine().getReasonPhrase());
                }
            } catch (IOException ex) {
                ex.printStackTrace();
                if (interaction != null) {
                    interaction.notify(PluginNotificationLevel.FATAL, "Failed to query the CrowdStrike web service " + ex.getMessage());
                }
            }
            catch (org.apache.http.ParseException ex) {
                ex.printStackTrace();
            }
        }
        return result;
    }
    
    
    public CrowdstrikeClient(String secret, String username)
    {
        this.secret = secret;
        this.username = username;
    }
   
}
