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
package au.gov.asd.acsc.constellation.plugins.importexport.jdbc;

import au.gov.asd.tac.constellation.graph.Graph;
import au.gov.asd.tac.constellation.graph.WritableGraph;
import au.gov.asd.tac.constellation.graph.locking.DualGraph;
import au.gov.asd.tac.constellation.graph.schema.SchemaFactory;

public class SchemaDestination extends ImportDestination<SchemaFactory> {

    public SchemaDestination(SchemaFactory destination) {
        super(destination);

        this.label = "New " + destination.getLabel();
    }

    @Override
    public Graph getGraph() {
        SchemaFactory schemaFactory = getDestination();

        Graph graph = new DualGraph(schemaFactory.createSchema());

        WritableGraph wg = graph.getWritableGraphNow("New Graph", true);
        try {
            graph.getSchema().newGraph(wg);
        } finally {
            wg.commit();
        }

        return graph;
    }
}
