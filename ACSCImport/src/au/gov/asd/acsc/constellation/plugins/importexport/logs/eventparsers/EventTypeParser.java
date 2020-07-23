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

import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.openide.util.Lookup;
import org.w3c.dom.Element;

public abstract class EventTypeParser {

    private static final Map<String, EventTypeParser> PARSERS = new LinkedHashMap<>();
    private static final Map<String, EventTypeParser> UNMODIFIABLE_PARSERS = Collections.unmodifiableMap(PARSERS);

    public static final EventTypeParser DEFAULT_PARSER = getParsers().values().iterator().next();

    private static synchronized void init() {
        if (PARSERS.isEmpty()) {
            final List<EventTypeParser> parsers = new ArrayList<>(Lookup.getDefault().lookupAll(EventTypeParser.class));
            Collections.sort(parsers, (EventTypeParser o1, EventTypeParser o2) -> {
                return Integer.compare(o1.position, o2.position);
            });
            parsers.stream().forEach(parser -> PARSERS.put(parser.label, parser));
        }
    }
    
    protected String getIPType(String ip)
    {
        if (ip.contains(":"))
        {
            return AnalyticConcept.VertexType.IPV6.toString();
        }
        else
        {
            return AnalyticConcept.VertexType.IPV4.toString();
        }
    }

    /**
     * Returns instances of all registered ImportFileParser classes mapped by
     * their names.
     * <p>
     * The map returned is unmodifiable and its iterators will return the
     * ImportFileParser instances in order of position (highest first).
     *
     * @return Instances of all registered ImportFileParser classes mapped by
     * their names.
     */
    public static Map<String, EventTypeParser> getParsers() {
        init();
        return UNMODIFIABLE_PARSERS;
    }

    /**
     * Returns the ImportFileParser with the specified name or null if no
     * ImportFileParser has been registered with that name.
     *
     * @param label the label of a registered ImportFileParser.
     *
     * @return the ImportFileParser with the specified name.
     */
    public static EventTypeParser getParser(final String label) {
        return UNMODIFIABLE_PARSERS.get(label);
    }

    private final String label;
    private final int position;

    /**
     * Creates a new ImportFileParser with a specified label and position.
     *
     * @param label the label of the ImportFileParser (displayed in the UI).
     * @param position the position of the ImportFileParser used for sorting a
     * list of parsers.
     */
    public EventTypeParser(final String label, final int position) {
        this.label = label;
        this.position = position;
    }

    /**
     * Returns the label of this ImportFileParser.
     *
     * @return the label of this ImportFileParser.
     */
    public final String getLabel() {
        return label;
    }

    /**
     * Returns the position of this ImportFileParser. The position is used to
     * sort a list of ImportFileParsers when displayed in the UI.
     *
     * @return the position of this ImportFileParser.
     */
    public final int getPosition() {
        return position;
    }

    @Override
    public String toString() {
        return label;
    }


    public PluginParameters getParameters() {
        return null;
    }

    public void updateParameters(final PluginParameters parameters) {

    }

    public abstract void parse(final Element input, RecordStore result, final PluginParameters parameters) throws IOException;
    public abstract boolean canParse(final Element input) throws IOException;

    
}
