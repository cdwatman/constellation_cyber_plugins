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
package au.gov.asd.acsc.constellation.schema.cyberschema.icons;

import au.gov.asd.tac.constellation.utilities.icon.ByteIconData;
import au.gov.asd.tac.constellation.utilities.icon.ConstellationIcon;
import au.gov.asd.tac.constellation.utilities.icon.ConstellationIconProvider;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.io.IOUtils;
import org.openide.util.lookup.ServiceProvider;

/**
 * An IconProvider defining icons which might be used for analysis purposes.
 *
 */


@ServiceProvider(service = ConstellationIconProvider.class)
public class CyberIconProvider implements ConstellationIconProvider {

    private static ByteIconData loadIcon(String name) {
        try {
            byte[] bytes = IOUtils.toByteArray(CyberIconProvider.class.getResourceAsStream(name));
            return new ByteIconData(bytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new ByteIconData(new byte[0]);
    }

    public static final ConstellationIcon ATTACK_PATTERN = new ConstellationIcon.Builder("Attack Pattern", loadIcon("attack_pattern.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon CAMPAIGN = new ConstellationIcon.Builder("Campaign", loadIcon("campaign.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon COURSE_OF_ACTION = new ConstellationIcon.Builder("Course of Action", loadIcon("course_of_action.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon GROUPING = new ConstellationIcon.Builder("Grouping", loadIcon("grouping.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon IDENTITY = new ConstellationIcon.Builder("Identity", loadIcon("identity.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon INDICATOR = new ConstellationIcon.Builder("Indicator", loadIcon("indicator.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon INFRASTRUCTURE = new ConstellationIcon.Builder("Infrastructure", loadIcon("infrastructure.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon INTRUSION_SET = new ConstellationIcon.Builder("Intrusion Set", loadIcon("intrusion_set.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon LOCATION = new ConstellationIcon.Builder("Location", loadIcon("location.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon MALWARE = new ConstellationIcon.Builder("Malware", loadIcon("malware.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon MALWARE_ANALYSIS = new ConstellationIcon.Builder("Malware Analysis", loadIcon("malware_analysis.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon NOTE = new ConstellationIcon.Builder("Note", loadIcon("note.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon OBSERVED_DATA = new ConstellationIcon.Builder("Observed Data", loadIcon("observed_data.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon OPINION = new ConstellationIcon.Builder("Opinion", loadIcon("opinion.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon RELATIONSHIP = new ConstellationIcon.Builder("Relationship", loadIcon("relationship.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon REPORT = new ConstellationIcon.Builder("Report", loadIcon("report.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon SIGHTING = new ConstellationIcon.Builder("Sighting", loadIcon("sighting.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon THREAT_ACTOR = new ConstellationIcon.Builder("Threat Actor", loadIcon("threat_actor.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon TOOL = new ConstellationIcon.Builder("Tool", loadIcon("tool.png"))
            .addCategory("STIX")
            .build();
    public static final ConstellationIcon VULNERABILITY = new ConstellationIcon.Builder("Vulnerability", loadIcon("vulnerability.png"))
            .addCategory("STIX")
            .build();

    @Override
    public List<ConstellationIcon> getIcons() {
        List<ConstellationIcon> cyberIcons = new ArrayList<>();
        
        cyberIcons.add(ATTACK_PATTERN);
        cyberIcons.add(CAMPAIGN);
        cyberIcons.add(COURSE_OF_ACTION);
        cyberIcons.add(GROUPING);
        cyberIcons.add(IDENTITY);
        cyberIcons.add(INDICATOR);
        cyberIcons.add(INFRASTRUCTURE);
        cyberIcons.add(INTRUSION_SET);
        cyberIcons.add(LOCATION);
        cyberIcons.add(MALWARE);
        cyberIcons.add(MALWARE_ANALYSIS);
        cyberIcons.add(NOTE);
        cyberIcons.add(OBSERVED_DATA);
        cyberIcons.add(OPINION);
        cyberIcons.add(RELATIONSHIP);
        cyberIcons.add(REPORT);
        cyberIcons.add(SIGHTING);
        cyberIcons.add(THREAT_ACTOR);
        cyberIcons.add(TOOL);
        cyberIcons.add(VULNERABILITY);
        
        return cyberIcons;
    }
}
