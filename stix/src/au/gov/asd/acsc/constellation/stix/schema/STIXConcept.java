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
package au.gov.asd.acsc.constellation.stix.schema;

import au.gov.asd.acsc.constellation.schema.cyberschema.icons.CyberIconProvider;
import au.gov.asd.tac.constellation.graph.GraphElementType;
import au.gov.asd.tac.constellation.graph.attribute.IntegerObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.LongObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.StringAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.BooleanObjectAttributeDescription;
import au.gov.asd.tac.constellation.graph.attribute.ZonedDateTimeAttributeDescription;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.attribute.SchemaAttribute;
import au.gov.asd.tac.constellation.graph.schema.concept.SchemaConcept;
import au.gov.asd.tac.constellation.graph.schema.type.SchemaVertexType;
import au.gov.asd.tac.constellation.utilities.icon.AnalyticIconProvider;
import au.gov.asd.tac.constellation.utilities.icon.CharacterIconProvider;
import au.gov.asd.tac.constellation.utilities.icon.UserInterfaceIconProvider;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.openide.util.lookup.ServiceProvider;

@ServiceProvider(service = SchemaConcept.class)
public class STIXConcept extends SchemaConcept {

    @Override
    public String getName() {
        return "STIX";
    }

    @Override
    public Set<Class<? extends SchemaConcept>> getParents() {
        final Set<Class<? extends SchemaConcept>> parentSet = new HashSet<>();
        parentSet.add(AnalyticConcept.class);
        return Collections.unmodifiableSet(parentSet);
    }

    public static class VertexType {
        
        public static final SchemaVertexType ATTACK_PATTERN = new SchemaVertexType.Builder("Attack Pattern")
                .setForegroundIcon(CyberIconProvider.ATTACK_PATTERN)
                .build();
        public static final SchemaVertexType CAMPAIGN = new SchemaVertexType.Builder("Campaign")
                .setForegroundIcon(CyberIconProvider.CAMPAIGN)
                .build();
        public static final SchemaVertexType COURSE_OF_ACTION = new SchemaVertexType.Builder("Course of Action")
                .setForegroundIcon(CyberIconProvider.COURSE_OF_ACTION)
                .build();
        public static final SchemaVertexType GROUPING = new SchemaVertexType.Builder("Grouping")
                .setForegroundIcon(CyberIconProvider.GROUPING)
                .build();
        public static final SchemaVertexType IDENTITY = new SchemaVertexType.Builder("Identity")
                .setForegroundIcon(CyberIconProvider.IDENTITY)
                .build();
        public static final SchemaVertexType INDICATOR = new SchemaVertexType.Builder("Indicator")
                .setForegroundIcon(CyberIconProvider.INDICATOR)
                .build();
        public static final SchemaVertexType INFRASTRUCTURE = new SchemaVertexType.Builder("Infrastructure")
                .setForegroundIcon(CyberIconProvider.INFRASTRUCTURE)
                .build();
        public static final SchemaVertexType INTRUSION_SET = new SchemaVertexType.Builder("Intrusion Set")
                .setForegroundIcon(CyberIconProvider.INTRUSION_SET)
                .build();
        public static final SchemaVertexType LOCATION = new SchemaVertexType.Builder("Location")
                .setForegroundIcon(CyberIconProvider.LOCATION)
                .build();
        public static final SchemaVertexType MALWARE = new SchemaVertexType.Builder("Malware")
                .setForegroundIcon(CyberIconProvider.MALWARE)
                .build();
        public static final SchemaVertexType MALWARE_ANALYSIS = new SchemaVertexType.Builder("Malware Analysis")
                .setForegroundIcon(CyberIconProvider.MALWARE_ANALYSIS)
                .build();
        public static final SchemaVertexType NOTE = new SchemaVertexType.Builder("Note")
                .setForegroundIcon(CyberIconProvider.NOTE)
                .build();
        public static final SchemaVertexType OBSERVED_DATA = new SchemaVertexType.Builder("Observed Data")
                .setForegroundIcon(CyberIconProvider.OBSERVED_DATA)
                .build();
        public static final SchemaVertexType OPINION = new SchemaVertexType.Builder("Opinion")
                .setForegroundIcon(CyberIconProvider.OPINION)
                .build();
        public static final SchemaVertexType RELATIONSHIP = new SchemaVertexType.Builder("Relationship")
                .setForegroundIcon(CyberIconProvider.RELATIONSHIP)
                .build();
        public static final SchemaVertexType REPORT = new SchemaVertexType.Builder("Report")
                .setForegroundIcon(CyberIconProvider.REPORT)
                .build();
        public static final SchemaVertexType SIGHTING = new SchemaVertexType.Builder("Sighting")
                .setForegroundIcon(CyberIconProvider.SIGHTING)
                .build();
        public static final SchemaVertexType THREAT_ACTOR = new SchemaVertexType.Builder("Threat Actor")
                .setForegroundIcon(CyberIconProvider.THREAT_ACTOR)
                .build();
        public static final SchemaVertexType TOOL = new SchemaVertexType.Builder("Tool")
                .setForegroundIcon(CyberIconProvider.TOOL)
                .build();
        public static final SchemaVertexType VULNERABILITY = new SchemaVertexType.Builder("Vulnerability")
                .setForegroundIcon(CyberIconProvider.VULNERABILITY)
                .build();
        public static final SchemaVertexType DOMAIN_NAME = new SchemaVertexType.Builder("Domain Name")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType ARTIFACT = new SchemaVertexType.Builder("Artifact")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType AUTONOMOUS_SYSTEM = new SchemaVertexType.Builder("Autonomous System")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType DIRECTORY = new SchemaVertexType.Builder("Directory")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType EMAIL_MESSAGE = new SchemaVertexType.Builder("Email Message")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType FILE = new SchemaVertexType.Builder("File")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType MAC_ADDRESS = new SchemaVertexType.Builder("MAC Address")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType MUTEX = new SchemaVertexType.Builder("Mutex")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType NETWORK_TRAFFIC = new SchemaVertexType.Builder("Network Traffic")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType PROCESS = new SchemaVertexType.Builder("Process")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType SOFTWARE = new SchemaVertexType.Builder("Software")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType USER_ACCOUNT = new SchemaVertexType.Builder("User Account")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType WINDOWS_REGISTRY_KEY = new SchemaVertexType.Builder("Windows Registry Key")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType X509_CERTIFICATE = new SchemaVertexType.Builder("x509 Certificate")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();
        public static final SchemaVertexType LANGUAGE = new SchemaVertexType.Builder("Language")
                .setForegroundIcon(AnalyticIconProvider.STAR)
                .build();

    }

    public static class TransactionAttribute {

        private TransactionAttribute() {
            // ignore
        }
/*
        public static final SchemaAttribute OFFSET = new SchemaAttribute.Builder(GraphElementType.TRANSACTION, StringAttributeDescription.ATTRIBUTE_NAME, "Offset")
                .setDescription("Offset")
                .build();
*/
        
    }

    @Override
    public List<SchemaVertexType> getSchemaVertexTypes() {
        final List<SchemaVertexType> schemaVertexTypes = new ArrayList<>();
        schemaVertexTypes.add(VertexType.ATTACK_PATTERN);
        schemaVertexTypes.add(VertexType.CAMPAIGN);
        schemaVertexTypes.add(VertexType.COURSE_OF_ACTION);
        schemaVertexTypes.add(VertexType.GROUPING);
        schemaVertexTypes.add(VertexType.IDENTITY);
        schemaVertexTypes.add(VertexType.INDICATOR);
        schemaVertexTypes.add(VertexType.INFRASTRUCTURE);
        schemaVertexTypes.add(VertexType.INTRUSION_SET);
        schemaVertexTypes.add(VertexType.LOCATION);
        schemaVertexTypes.add(VertexType.MALWARE);
        schemaVertexTypes.add(VertexType.MALWARE_ANALYSIS);
        schemaVertexTypes.add(VertexType.NOTE);
        schemaVertexTypes.add(VertexType.OBSERVED_DATA);
        schemaVertexTypes.add(VertexType.OPINION);
        schemaVertexTypes.add(VertexType.RELATIONSHIP);
        schemaVertexTypes.add(VertexType.REPORT);
        schemaVertexTypes.add(VertexType.SIGHTING);
        schemaVertexTypes.add(VertexType.THREAT_ACTOR);
        schemaVertexTypes.add(VertexType.TOOL);
        schemaVertexTypes.add(VertexType.VULNERABILITY);
        schemaVertexTypes.add(VertexType.DOMAIN_NAME);
        schemaVertexTypes.add(VertexType.ARTIFACT);
        schemaVertexTypes.add(VertexType.AUTONOMOUS_SYSTEM);
        schemaVertexTypes.add(VertexType.DIRECTORY);
        schemaVertexTypes.add(VertexType.EMAIL_MESSAGE);
        schemaVertexTypes.add(VertexType.FILE);
        schemaVertexTypes.add(VertexType.MAC_ADDRESS);
        schemaVertexTypes.add(VertexType.MUTEX);
        schemaVertexTypes.add(VertexType.NETWORK_TRAFFIC);
        schemaVertexTypes.add(VertexType.PROCESS);
        schemaVertexTypes.add(VertexType.SOFTWARE);
        schemaVertexTypes.add(VertexType.USER_ACCOUNT);
        schemaVertexTypes.add(VertexType.WINDOWS_REGISTRY_KEY);
        schemaVertexTypes.add(VertexType.X509_CERTIFICATE);
        schemaVertexTypes.add(VertexType.LANGUAGE);
        return Collections.unmodifiableList(schemaVertexTypes);
    }

    public static class VertexAttribute {
        /*
        public static final SchemaAttribute FAMILY_TYPE = new SchemaAttribute.Builder(GraphElementType.VERTEX, StringAttributeDescription.ATTRIBUTE_NAME, "Family Type")
                .build();
        */

    }

    @Override
    public Collection<SchemaAttribute> getSchemaAttributes() {
        final List<SchemaAttribute> attributes = new ArrayList<>();
        /*attributes.add(VertexAttribute.OBSERVATION_TYPE);*/
        
        return Collections.unmodifiableCollection(attributes);
    }
}
