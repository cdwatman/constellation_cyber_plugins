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
package au.gov.asd.acsc.constellation.plugins.importexport.logs;

import au.gov.asd.acsc.constellation.schema.cyberschema.concept.CyberConcept;
import au.gov.asd.tac.constellation.graph.schema.attribute.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.concept.SchemaConcept;
import au.gov.asd.tac.constellation.graph.schema.type.SchemaTransactionType;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.openide.util.lookup.ServiceProvider;

@ServiceProvider(service = SchemaConcept.class)
public class WindowsLogsConcept extends SchemaConcept {

    @Override
    public String getName() {
        return "Windows Logs";
    }
    
    public static class TransactionType {
        
        public static final SchemaTransactionType WFC_ALLOWED_CONNECTION = new SchemaTransactionType.Builder("WFC Allowed Connection")
                .setDescription("WFC Allowed Connection")
                .setDirected(true)
                .build();
        public static final SchemaTransactionType LOG_CLEARED = new SchemaTransactionType.Builder("Security Log Cleared")
                .setDescription("Security Log Cleared")
                .setDirected(false)
                .build();
    }
    
    @Override
    public List<SchemaTransactionType> getSchemaTransactionTypes() {
        final List<SchemaTransactionType> schemaTransactionTypes = new ArrayList<>();
        schemaTransactionTypes.add(TransactionType.WFC_ALLOWED_CONNECTION);
        schemaTransactionTypes.add(TransactionType.LOG_CLEARED);
        return schemaTransactionTypes;
    }

    public static class VertexAttribute {

        private VertexAttribute() {
            
        }
    }

    @Override
    public Collection<SchemaAttribute> getSchemaAttributes() {
        final List<SchemaAttribute> schemaAttributes = new ArrayList<>();
        
        return schemaAttributes;
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getParents() {
        final Set<Class<? extends SchemaConcept>> parentSet = new HashSet<>();
        parentSet.add(CyberConcept.class);
        return parentSet;
    }
}
