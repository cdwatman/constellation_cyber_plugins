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

import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.PluginNotificationLevel;
import au.gov.asd.tac.constellation.security.proxy.ConstellationHttpProxySelector;
import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.python.google.common.net.UrlEscapers;

public class DomainToolsClient 
{
    String apiKey = null;
    String username = null;
    String apiBase = "https://api.domaintools.com/v1";
    
    private JSONObject query(String query, PluginInteraction interaction)
    {
        int page = 0;
        JSONObject res = null;
        int retry = 0;
        while (true && retry < 3)
        {
            page++;
            JSONObject out = queryService(query, interaction);
            
            if (out != null)
            {
                if (out.has("error"))
                {
                    JSONObject error = out.getJSONObject("error");
                    if (error.getInt("code") == 206)
                    {
                        return new JSONObject(); // failed to parse, just return
                    }
                    else
                    {
                        interaction.notify(PluginNotificationLevel.FATAL, error.getString("message"));
                        return null;
                    }
                }
                else
                {
                    return out;
                }
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
    
    private JSONObject queryService(String query, PluginInteraction interaction)
    {
        JSONObject result = null;
        String c = "";
        if (query.contains("?"))
        {
            c = String.format("&api_username=%s&api_key=%s", username, apiKey);
        }
        else
        {
            c = String.format("?api_username=%s&api_key=%s", username, apiKey);
        }

        
        try {
            ProxySelector sel = ConstellationHttpProxySelector.getDefault();
            List<Proxy> proxies = sel.select(new URI(query));
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
                HttpGet get = new HttpGet(query + c);
                CloseableHttpResponse resp;
                try {
                    resp = client.execute(get);
                } catch (IOException ex) {
                    if (interaction != null) {
                        interaction.notify(PluginNotificationLevel.FATAL, "Failed to query the DomainTools web service " + ex.getMessage());
                    }
                    return null;
                }

                try {
                    if (resp.getStatusLine().getStatusCode() == 200) {
                        String answer = EntityUtils.toString(resp.getEntity());
                        result = new JSONObject(answer);
                    }
                    else if (resp.getStatusLine().getStatusCode() == 401) { // unauthorised
                        String answer = EntityUtils.toString(resp.getEntity());
                        result = new JSONObject(answer);
                    }
                    else {
                        return null;
                    }
                } catch (IOException ex) {
                    if (interaction != null) {
                        interaction.notify(PluginNotificationLevel.FATAL, "Could not read from the DomainTools web service.");
                    }
                    return null;
                } catch (org.apache.http.ParseException ex) {
                    ex.printStackTrace();
                    return null;
                }
                break;
            }

        } catch (URISyntaxException ex) {
            ex.printStackTrace();
        }
        return result;
    }
    
    public DomainToolsClient(String apiKey, String username)
    {
        this.apiKey = apiKey;
        this.username = username;
    }
    
    public JSONObject searchWhois(String query, PluginInteraction interaction)
    {
        return query(String.format("%s/%s/whois/parsed", apiBase, UrlEscapers.urlPathSegmentEscaper().escape(query)), interaction);
    }
    
    public JSONObject searchProfile(String query, PluginInteraction interaction)
    {
        return query(String.format("%s/%s/", apiBase, UrlEscapers.urlPathSegmentEscaper().escape(query)), interaction);
    }    
}
