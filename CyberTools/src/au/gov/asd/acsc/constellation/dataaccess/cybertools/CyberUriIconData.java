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
package au.gov.asd.acsc.constellation.dataaccess.cybertools;

import au.gov.asd.tac.constellation.utilities.icon.IconData;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;


public class CyberUriIconData extends IconData {

    private static final Logger LOGGER = Logger.getLogger(CyberUriIconData.class.getName());
    private final URI uri;
    private final CloseableHttpClient client;
    

    public CyberUriIconData(final String uriString, final CloseableHttpClient client) {
        this.uri = URI.create(uriString);
        assert uri.isAbsolute();
        this.client = client;
    }

    public CyberUriIconData(final URI uri, final CloseableHttpClient client) {
        this.uri = uri;
        assert uri.isAbsolute();
        this.client = client;
    }

    @Override
    protected InputStream createInputStream() throws IOException {
        InputStream stream = null;
        try {
            if (uri.getScheme().toUpperCase().equals("HTTPS")) {
                
                HttpGet get = new HttpGet(uri);
                
                try (CloseableHttpResponse resp = client.execute(get) ){
                    if (resp.getStatusLine().getStatusCode() == 200 || resp.getStatusLine().getStatusCode() == 304) {
                        stream =  resp.getEntity().getContent();
                    }
                } catch (IOException | org.apache.http.ParseException ex) {
                    ex.printStackTrace();
                }
                
            } else {
                stream = uri.toURL().openStream();
            }
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
            LOGGER.log(Level.WARNING, "UriIconData: file not found at {0}", uri.toString());
        }

        return stream;
    }
}
