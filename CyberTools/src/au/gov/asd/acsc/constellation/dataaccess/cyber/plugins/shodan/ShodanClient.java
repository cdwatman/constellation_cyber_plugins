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
import org.json.JSONArray;
import org.json.JSONObject;

public class ShodanClient 
{
    String apiKey = null;
    String apiBase = "https://api.shodan.io";
    
    private JSONObject query(String query, PluginInteraction interaction)
    {
        int page = 0;
        JSONObject res = null;
        int retry = 0;
        while (true && retry < 10)
        {
            page++;
            JSONObject out = query(query, page, interaction);
            
            if (out != null)
            {
                if (out.has("error"))
                {
                    if (((String)out.get("error")).contains("Insufficient query credits"))
                    {
                        interaction.notify(PluginNotificationLevel.FATAL, "Insufficient query credits, please upgrade your API plan or wait for the monthly limit to reset");
                        return res;
                    }
                    else
                    {
                        try {
                            Thread.sleep(5000);
                        } catch (InterruptedException ex) {
                            return null;
                        }
                    }
                }
                else if (out.has("matches"))
                {

                    JSONArray arr = out.getJSONArray("matches");

                    if (res == null)
                    {
                        res = out;
                    }
                    else
                    {    
                        
                        for (Object o : arr)
                        {
                            res.getJSONArray("matches").put(o);
                        }
                    }

                    if (arr.length() < 100 || out.getInt("total") < 100)
                    {
                        break;
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
    
    private JSONObject query(String query, Integer page, PluginInteraction interaction)
    {
        JSONObject result = null;
        String c = "";
        if (query.contains("?"))
        {
            c = String.format("&key=%s",apiKey);
        }
        else
        {
            c = String.format("?key=%s",apiKey);
        }
        if (page != null)
        {
            c += String.format("&page=%s", page);
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
                        interaction.notify(PluginNotificationLevel.FATAL, "Failed to query the Shodan web service " + ex.getMessage());
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
                        interaction.notify(PluginNotificationLevel.FATAL, "Could not read from the Shodan web service.");
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
    
    public ShodanClient(String apiKey)
    {
        this.apiKey = apiKey;
    }
    
    public JSONObject search(String query, PluginInteraction interaction)
    {
        return query(String.format("%s%s?query=%s", apiBase,"/shodan/host/search", query), interaction);
    }
    
    public Integer searchCount(String query, PluginInteraction interaction)
    {
        Integer o = null;
        
        JSONObject countObj = query(String.format("%s%s?query=%s", apiBase,"/shodan/host/count", query), null, interaction);
        if (countObj != null)
        {
            Integer l = countObj.getInt("total");
            return l;
        }
        return o;
    }   
}
