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
package au.gov.asd.acsc.constellation.stix.importstix;

import au.gov.asd.acsc.constellation.schema.cyberschema.concept.CyberConcept;
import au.gov.asd.acsc.constellation.stix.schema.STIXConcept;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStore;
import au.gov.asd.tac.constellation.graph.processing.GraphRecordStoreUtilities;
import au.gov.asd.tac.constellation.graph.processing.RecordStore;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.AnalyticConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.ContentConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.SpatialConcept;
import au.gov.asd.tac.constellation.graph.schema.analytic.concept.TemporalConcept;
import au.gov.asd.tac.constellation.graph.schema.type.SchemaVertexType;
import au.gov.asd.tac.constellation.graph.schema.visual.concept.VisualConcept;
import au.gov.asd.tac.constellation.plugins.Plugin;
import au.gov.asd.tac.constellation.plugins.PluginException;
import au.gov.asd.tac.constellation.plugins.PluginInteraction;
import au.gov.asd.tac.constellation.plugins.PluginNotificationLevel;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameter;
import au.gov.asd.tac.constellation.plugins.parameters.PluginParameters;
import au.gov.asd.tac.constellation.plugins.parameters.types.BooleanParameterType;
import au.gov.asd.tac.constellation.plugins.parameters.types.BooleanParameterType.BooleanParameterValue;
import au.gov.asd.tac.constellation.plugins.parameters.types.FileParameterType;
import au.gov.asd.tac.constellation.plugins.parameters.types.FileParameterType.FileParameterValue;
import au.gov.asd.tac.constellation.utilities.temporal.TemporalFormatting;
import au.gov.asd.tac.constellation.views.dataaccess.templates.RecordStoreQueryPlugin;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import javafx.stage.FileChooser.ExtensionFilter;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.openide.util.Exceptions;
import org.openide.util.NbBundle;
import org.openide.util.lookup.ServiceProvider;
import org.openide.util.lookup.ServiceProviders;


@ServiceProviders({
    @ServiceProvider(service = Plugin.class)
})
@NbBundle.Messages("StixFileImporterPlugin=Import STIX File")
public class StixFileImporterPlugin extends RecordStoreQueryPlugin  {

    private static final Logger LOGGER = Logger.getLogger(StixFileImporterPlugin.class.getName());

    /**
     * When an attribute is not assigned to a column, the value is -145355 so
     * its easier to track down if there is an error.
     */
    public static final int ATTRIBUTE_NOT_ASSIGNED_TO_COLUMN = -145355;

    public static final String FILEPATH_PARAMETER_ID = PluginParameter.buildId(StixFileImporterPlugin.class, "path");
    public static final String SHOW_REFERENCES_PARAMETER_ID = PluginParameter.buildId(StixFileImporterPlugin.class, "showReferences");
    
    /* These HashMaps contain the common mappings from the stix json to the attribute names in constellation */
    private HashMap<String, String> stringListMappings = new HashMap<>();
    private HashMap<String, String> integerMappings = new HashMap<>();
    private HashMap<String, String> booleanMappings = new HashMap<>();
    private HashMap<String, String> timestampMappings = new HashMap<>();
    private HashMap<String, String> stringMappings = new HashMap<>();
    
    public StixFileImporterPlugin()
    {
        super();
        
        stringListMappings.put("languages","Languages");
        stringListMappings.put("implementation_languages","Languages");
        stringListMappings.put("protocols","Protocols");
        stringListMappings.put("tool_types","Tool Types");
        stringListMappings.put("personal_motivations","Personal Motivations");
        stringListMappings.put("threat_actor_types","Threat Actor Types");
        stringListMappings.put("report_types","Report Types");
        stringListMappings.put("authors","Authors");
        stringListMappings.put("modules","Modules");
        stringListMappings.put("capabilities","Capabilities");
        stringListMappings.put("architecture_execution_envs","Architectures");
        stringListMappings.put("malware_types","Malware Types");
        stringListMappings.put("secondary_motivations","Secondary motivations");
        stringListMappings.put("goals","Goals");
        stringListMappings.put("infrastructure_types","Infrastructure Types");
        stringListMappings.put("indicator_types","Indicator Types");
        stringListMappings.put("sectors","Sectors");
        stringListMappings.put("roles","Roles");
        stringListMappings.put("aliases","Aliases");
        stringListMappings.put("labels","Labels");

        integerMappings.put("number_of_subkeys","Number of subkeys");
        integerMappings.put("subject_public_key_exponent","Subject public key exponent");
        integerMappings.put("dst_packets","Destination Packets");
        integerMappings.put("src_packets","Source Packets");
        integerMappings.put("dst_byte_count","Destination byte count");
        integerMappings.put("src_byte_count","Source byte count");
        integerMappings.put("dst_port","Destination port");
        integerMappings.put("src_port","Source port");
        integerMappings.put("size","Size");
        integerMappings.put("number","Number");
        integerMappings.put("confidence","Confidence");

        booleanMappings.put("is_self_signed","Is self signed");
        booleanMappings.put("is_disabled","Is disabled");
        booleanMappings.put("can_escalate_privs","Can escalate privs");
        booleanMappings.put("is_privileged","Is Privileged");
        booleanMappings.put("is_service_account","Is Service Account");
        booleanMappings.put("is_hidden","Is hidden");
        booleanMappings.put("is_active","Is active");
        booleanMappings.put("is_multipart","Is multipart");
        booleanMappings.put("is_family","Is malware family");
        booleanMappings.put("revoked","Revoked");

        timestampMappings.put("validity_not_after","Validity not after");
        timestampMappings.put("validity_not_before","Validity not before");
        timestampMappings.put("valid_from","Valid from");
        timestampMappings.put("valid_until","Valid until");
        timestampMappings.put("modified_time",TemporalConcept.VertexAttribute.MODIFIED.getName());
        timestampMappings.put("account_last_login","Account last login");
        timestampMappings.put("account_first_login","Account first login");
        timestampMappings.put("credential_last_changed","Credential last changed");
        timestampMappings.put("account_expires","Account expires");
        timestampMappings.put("object_modified",TemporalConcept.VertexAttribute.MODIFIED.getName());
        timestampMappings.put("modified",TemporalConcept.VertexAttribute.MODIFIED.getName());
        timestampMappings.put("account_created",TemporalConcept.VertexAttribute.CREATED.getName());
        timestampMappings.put("created",TemporalConcept.VertexAttribute.CREATED.getName());
        timestampMappings.put("created_time",TemporalConcept.VertexAttribute.CREATED.getName());
        timestampMappings.put("date",TemporalConcept.VertexAttribute.DATETIME.getName());
        timestampMappings.put("atime","Accessed Time");
        timestampMappings.put("mtime",TemporalConcept.VertexAttribute.MODIFIED.getName());
        timestampMappings.put("ctime",TemporalConcept.VertexAttribute.CREATED.getName());
        timestampMappings.put("stop_time",TemporalConcept.VertexAttribute.END_TIME.getName());
        timestampMappings.put("start_time",TemporalConcept.VertexAttribute.START_TIME.getName());
        timestampMappings.put("published", "Published");
        timestampMappings.put("last_observed",TemporalConcept.VertexAttribute.LAST_SEEN.getName());
        timestampMappings.put("last_seen",TemporalConcept.VertexAttribute.LAST_SEEN.getName());
        timestampMappings.put("first_observed",TemporalConcept.VertexAttribute.FIRST_SEEN.getName());
        timestampMappings.put("first_seen",TemporalConcept.VertexAttribute.FIRST_SEEN.getName());
        timestampMappings.put("analysis_ended","Analysis ended");
        timestampMappings.put("analysis_started","Analysis started");
        timestampMappings.put("submitted","Submitted");
        
        stringMappings.put("subject","Subject");
        stringMappings.put("issuer","Issuer");
        stringMappings.put("signature_algorithm","Signature algorithm");
        stringMappings.put("serial_number","Serial Number");
        stringMappings.put("subject_public_key_algorithm","Subject public key algorithm");
        stringMappings.put("subject_public_key_modulus","Subject public key modulus");
        stringMappings.put("key","Key");
        stringMappings.put("definition_type","Definition type");
        stringMappings.put("account_type","Account type");
        stringMappings.put("account_login","Account Login");
        stringMappings.put("credential","Credential");
        stringMappings.put("user_id","User Id");
        stringMappings.put("vendor","Vendor");
        stringMappings.put("swid","Software Id");
        stringMappings.put("cpe","Common Platform Enumeration");
        stringMappings.put("command_line","Command line");
        stringMappings.put("cwd","Current working directory");
        stringMappings.put("pid","Process Id");
        stringMappings.put("magic_number_hex","Magic Number");
        stringMappings.put("name_enc","Name encoding");
        stringMappings.put("content_disposition","Content Disposition");
        stringMappings.put("body","Body");
        stringMappings.put("subject","Subject");
        stringMappings.put("message_id","Message Id");
        stringMappings.put("content_type","Content Type");
        stringMappings.put("display_name","Display name");
        stringMappings.put("value","Value");
        stringMappings.put("path_enc","Path encoding");
        stringMappings.put("path","Path");
        stringMappings.put("rir","Regional Internet Registry");
        stringMappings.put("decryption_key","Decryption key");
        stringMappings.put("encryption_algorithm","Encryption algorithm");
        stringMappings.put("url","URL");
        stringMappings.put("payload_bin","Base64 Payload Binary");
        stringMappings.put("mime_type","MIME Type");
        stringMappings.put("summary","Summary");
        stringMappings.put("relationship_type","Relationship type");
        stringMappings.put("tool_version","Tool Version");
        stringMappings.put("sophistication","Sophistication");
        stringMappings.put("opinion","Opinion");
        stringMappings.put("explanation","Explanation");
        stringMappings.put("number_observed","Number observed");
        stringMappings.put("content",ContentConcept.VertexAttribute.CONTENT.getName());
        stringMappings.put("abstract","Abstract");
        stringMappings.put("result","Result");
        stringMappings.put("result_name","Result Name");
        stringMappings.put("analysis_definition_version","Analysis definition version");
        stringMappings.put("analysis_engine_version","Analysis engine version");
        stringMappings.put("configuration_version","Configuration version");
        stringMappings.put("version","Version");
        stringMappings.put("product","Product");
        stringMappings.put("postal_code", "Postal code");
        stringMappings.put("street_address","Street");
        stringMappings.put("city","City");
        stringMappings.put("administrative_area","State");
        stringMappings.put("country",SpatialConcept.VertexAttribute.COUNTRY.getName());
        stringMappings.put("region","Region");
        stringMappings.put("primary_motivation","Primary Motivation");
        stringMappings.put("resource_llevel","Resource level");
        stringMappings.put("pattern_version","Pattern version");
        stringMappings.put("pattern_type","Pattern type");
        stringMappings.put("pattern","Pattern");
        stringMappings.put("contact_information","Contact Information");
        stringMappings.put("identity_class","Identity type");
        stringMappings.put("context","Context");
        stringMappings.put("action","Action");
        stringMappings.put("objective","Objective");
        stringMappings.put("description", ContentConcept.VertexAttribute.DESCRIPTION.getName());
        stringMappings.put("lang","Language");
                
    }

    @Override
    public PluginParameters createParameters() {
        final PluginParameters params = new PluginParameters();
        
        final PluginParameter<FileParameterValue> filePathParam = FileParameterType.build(FILEPATH_PARAMETER_ID);
        filePathParam.setName("File to parse");
        filePathParam.setDescription("File to parse");
        FileParameterType.setKind(filePathParam, FileParameterType.FileParameterKind.OPEN);
        FileParameterType.setFileFilters(filePathParam, new ExtensionFilter("STIX 2 file","*.json"));
        params.addParameter(filePathParam);
        
        final PluginParameter<BooleanParameterValue> showReferencesParam = BooleanParameterType.build(SHOW_REFERENCES_PARAMETER_ID);
        filePathParam.setName("Show References");
        params.addParameter(showReferencesParam);
        
        return params;
    }
    
    private boolean isObject(JSONObject obj)
    {
       if ( !((String)obj.getOrDefault("type", "")).equalsIgnoreCase("relationship") )
       {
           return true;
       }
       return false;
    }
    
    private String getVertexType(String type)
    {
        String r = type;
        switch (type)
        {
            case "attack-pattern":
                r = STIXConcept.VertexType.ATTACK_PATTERN.getName();
                break;
            case "campaign":
                r = STIXConcept.VertexType.CAMPAIGN.getName();
                break;
            case "course-of-action":
                r = STIXConcept.VertexType.COURSE_OF_ACTION.getName();
                break;
            case "grouping":
                r = STIXConcept.VertexType.GROUPING.getName();
                break;
            case "identity":
                r = STIXConcept.VertexType.IDENTITY.getName();
                break;
            case "indicator":
                r = STIXConcept.VertexType.INDICATOR.getName();
                break;
            case "infrastructure":
                r = STIXConcept.VertexType.INFRASTRUCTURE.getName();
                break;
            case "intrusion-set":
                r = STIXConcept.VertexType.INTRUSION_SET.getName();
                break;
            case "location":
                r = STIXConcept.VertexType.LOCATION.getName();
                break;
            case "malware":
                r = STIXConcept.VertexType.MALWARE.getName();
                break;
            case "malware-analysis":
                r = STIXConcept.VertexType.MALWARE_ANALYSIS.getName();
                break;
            case "note":
                r = STIXConcept.VertexType.NOTE.getName();
                break;
            case "observed-data":
                r = STIXConcept.VertexType.OBSERVED_DATA.getName();
                break;
            case "opinion":
                r = STIXConcept.VertexType.OPINION.getName();
                break;
            case "relationship":
                r = STIXConcept.VertexType.RELATIONSHIP.getName();
                break;
            case "report":
                r = STIXConcept.VertexType.REPORT.getName();
                break;
            case "sighting":
                r = STIXConcept.VertexType.SIGHTING.getName();
                break;
            case "threat-actor":
                r = STIXConcept.VertexType.THREAT_ACTOR.getName();
                break;
            case "tool":
                r = STIXConcept.VertexType.TOOL.getName();
                break;
            case "vulnerability":
                r = STIXConcept.VertexType.CAMPAIGN.getName();
                break;
            case "artifact":
                r = STIXConcept.VertexType.ARTIFACT.getName();
                break;
            case "autonomous-system":
                r = STIXConcept.VertexType.AUTONOMOUS_SYSTEM.getName();
                break;
            case "directory":
                r = STIXConcept.VertexType.DIRECTORY.getName();
                break;
            case "domain-name":
                r = STIXConcept.VertexType.DOMAIN_NAME.getName();
                break;
            case "email-addr":
                r = AnalyticConcept.VertexType.EMAIL_ADDRESS.getName();
                break;
            case "email-message":
                r = STIXConcept.VertexType.EMAIL_MESSAGE.getName();
                break;
            case "file":
                r = STIXConcept.VertexType.FILE.getName();
                break;
            case "ipv4-addr":
                r = AnalyticConcept.VertexType.IPV4.getName();
                break;
            case "ipv6-addr":
                r = AnalyticConcept.VertexType.IPV6.getName();
                break;
            case "mac-addr":
                r = STIXConcept.VertexType.MAC_ADDRESS.getName();
                break;
            case "mutex":
                r = STIXConcept.VertexType.MUTEX.getName();
                break;
            case "network-traffic":
                r = STIXConcept.VertexType.NETWORK_TRAFFIC.getName();
                break;
            case "process":
                r = STIXConcept.VertexType.PROCESS.getName();
                break;
            case "software":
                r = STIXConcept.VertexType.SOFTWARE.getName();
                break;
            case "url":
                r = AnalyticConcept.VertexType.URL.getName();
                break;
            case "user-account":
                r = STIXConcept.VertexType.USER_ACCOUNT.getName();
                break;
            case "windows-registry-key":
                r = STIXConcept.VertexType.WINDOWS_REGISTRY_KEY.getName();
                break;
            case "x509-certificate":
                r = STIXConcept.VertexType.X509_CERTIFICATE.getName();
                break;
            case "language-content":
                r = STIXConcept.VertexType.LANGUAGE.getName();
                break;
        }
        
        return r;
    }
    
     
    
    private void drawObject(JSONObject obj, String end, HashMap<String, JSONObject> bundle, RecordStore result, boolean showReferences)
    {
        String label = (String)obj.get("name");
        String type = getVertexType((String)obj.get("type"));
        
        result.add();
        result.set(end + VisualConcept.VertexAttribute.IDENTIFIER, label);
        result.set(end + AnalyticConcept.VertexAttribute.TYPE, type);
        
        for (Object k : obj.keySet())
        {
            String key = (String)k;
            if (stringMappings.containsKey(key))
            {
                result.set(end + stringMappings.get(key), (String)obj.get(key) );
            }
            else if (timestampMappings.containsKey(key))
            {
                String dt = (String)obj.get(key);
                if (!dt.contains("."))
                {
                    dt = dt.substring(0, 19) + ".000Z";
                }
                result.set(end + timestampMappings.get(key), TemporalFormatting.completeZonedDateTimeString(dt) );
            }
            else if (booleanMappings.containsKey(key))
            {
                result.set(end + booleanMappings.get(key), (Boolean)obj.get(key) );
            }
            else if (integerMappings.containsKey(key))
            {
                result.set(end + integerMappings.get(key), (Integer)obj.get(key) );
            }
            else if (stringListMappings.containsKey(key))
            {
                result.set(end + stringListMappings.get(key), String.join(", ", (JSONArray)obj.get(key)));
            }
        }
        
        // contents property from language objects not mapped at this stage.
        // definition marking not draw at this stage, may be added in future.       

        /* do the mapping now for the non common attributes */
        
        if (obj.containsKey("kill_chain_phases"))
        {
            String out = "";
            for (Object o : (JSONArray)obj.get("kill_chain_phases"))
            {
               JSONObject kcp = (JSONObject)o;
               out += String.format("%s(%s)\n", StringUtils.capitalize( ((String)kcp.get("phase_name")).replace("-", " ")), StringUtils.capitalize(((String)kcp.get("kill_chain_name")).replace("-", " ")));
            }
            
            result.set(end + "Kill Chain Phases", out.trim() );
        }
        if (obj.containsKey("latitude"))
        {
            result.set(GraphRecordStoreUtilities.SOURCE + SpatialConcept.VertexAttribute.LATITUDE, (Float)obj.get("latitude"));
        }
        if (obj.containsKey("longitude"))
        {
            result.set(end + SpatialConcept.VertexAttribute.LONGITUDE, (Float)obj.get("longitude"));
        }
        if (obj.containsKey("precision"))
        {
            result.set(end + SpatialConcept.VertexAttribute.PRECISION, (Float)obj.get("precision"));
        }
        if (obj.containsKey("received_lines"))
        {
            result.set(end + "Received", String.join("\n", (JSONArray)obj.get("received_lines")));
        }
        if (obj.containsKey("additional_header_fields"))
        {
            JSONObject ahf = (JSONObject)obj.get("additional_header_fields");
            StringBuilder temp = new StringBuilder();
            for (Object key : ahf.keySet())
            {
                temp.append(String.format("%s:  %s\n", (String)key, (String)ahf.get(key)));
            }
            result.set(end + "Additional Headers", temp.toString().trim());
        }
        if (obj.containsKey("values"))
        {
            JSONArray ahf = (JSONArray)obj.get("values");
            StringBuilder temp = new StringBuilder();
            for (Object o : ahf)
            {
                JSONObject o1 = (JSONObject)o;
                temp.append(String.format("Name: %s Data:%s Data Type:%s\n", (String)o1.getOrDefault("name", ""), (String)o1.getOrDefault("data", ""), (String)o1.getOrDefault("data_type", "")   ));
            }
            result.set(end + "Registry keys", temp.toString().trim());
        }
        if (obj.containsKey("ipfix"))
        {
            JSONObject ahf = (JSONObject)obj.get("ipfix");
            StringBuilder temp = new StringBuilder();
            for (Object key : ahf.keySet())
            {
                temp.append(String.format("%s:  %s\n", (String)key, (String)ahf.get(key)));
            }
            result.set(end + "IP Flow Information Export", temp.toString().trim());
        }
        if (obj.containsKey("x509_v3_extensions"))
        {
            JSONObject o = (JSONObject)obj.get("x509_v3_extensions");
                    
            result.set(end + "Basic Constraints", (String)o.get("basic_constraints") );
            result.set(end + "Name Constraints", (String)o.get("name_constraints") );
            result.set(end + "Policy Constraints", (String)o.get("policy_constraints") );
            result.set(end + "Key usage", (String)o.get("key_usage") );
            result.set(end + "Extended Key usage", (String)o.get("extended_key_usage") );
            result.set(end + "Subject key identifier", (String)o.get("subject_key_identifier") );
            result.set(end + "Authority key identifier", (String)o.get("authority_key_identifier") );
            result.set(end + "Subject alternative name", (String)o.get("subject_alternative_name") );
            result.set(end + "Issuer alternative name", (String)o.get("issuer_alternative_name") );
            result.set(end + "Subject directory attributes", (String)o.get("subject_directory_attributes") );
            result.set(end + "CRL distribution points", (String)o.get("crl_distribution_points") );
            result.set(end + "Inhibit any policy", (String)o.get("inhibit_any_policy") );
            result.set(end + "Certificate policies", (String)o.get("certificate_policies") );
            result.set(end + "Policy mappings", (String)o.get("policy_mappings") );
            result.set(end + "Private Key usage not before", TemporalFormatting.completeZonedDateTimeString((String)obj.get("private_key_usage_period_not_before")) );
            result.set(end + "Private Key usage not after", TemporalFormatting.completeZonedDateTimeString((String)obj.get("private_key_usage_period_not_after")) );
        }
        if (obj.containsKey("environment_variables"))
        {
            JSONObject ahf = (JSONObject)obj.get("environment_variables");
            StringBuilder temp = new StringBuilder();
            for (Object key : ahf.keySet())
            {
                temp.append(String.format("%s:  %s\n", (String)key, (String)ahf.get(key)));
            }
            result.set(end + "Environment variables", temp.toString().trim());
        }
        
      
        /* Now for the more complex elements that create linked nodes */
        if (obj.containsKey("extensions"))
        {
            // file extensions property not handled at this stage, maybe added if needed in future            
        }
        
        if (obj.containsKey("child_refs"))
        {
            drawBasicLinkedNodes(label, type, "child_refs", "Child", obj, bundle, result);
        }
        
        if (obj.containsKey("parent_ref"))
        {
            drawBasicLinkedNode(label, type, "parent_ref", "Parent", obj, bundle, result);
        }
        
        if (obj.containsKey("image_ref"))
        {
            drawBasicLinkedNode(label, type, "image_ref", "Image", obj, bundle, result);
        }
        
        if (obj.containsKey("creator_user_ref"))
        {
            drawBasicLinkedNode(label, type, "creator_user_ref", "Creator", obj, bundle, result);
        }
        
        if (obj.containsKey("opened_connection_refs"))
        {
            drawBasicLinkedNodes(label, type, "opened_connection_refs", "Opened Connection", obj, bundle, result);
        }  
        
        if (obj.containsKey("encapsulated_by_ref"))
        {
            drawBasicLinkedNode(label, type, "encapsulated_by_ref", "Encapsulated By", obj, bundle, result);
        }
        
        if (obj.containsKey("encapsulates_refs"))
        {
            drawBasicLinkedNodes(label, type, "encapsulates_refs", "Encapsulates", obj, bundle, result);
        }  
        
        if (obj.containsKey("src_payload_ref"))
        {
            drawBasicLinkedNode(label, type, "src_payload_ref", "Source Payload", obj, bundle, result);
        }
        
        if (obj.containsKey("dst_payload_ref"))
        {
            drawBasicLinkedNode(label, type, "dst_payload_ref", "Destination Payload", obj, bundle, result);
        }
        
        if (obj.containsKey("src_ref"))
        {
            JSONObject o1 = bundle.get((String)obj.get("src_ref"));
            if (o1 != null)
            {
                result.add();
                result.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, label);
                result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, type);

                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, (String)o1.get("name"));
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, getVertexType((String)o1.get("type")));

                result.set(GraphRecordStoreUtilities.TRANSACTION + GraphRecordStoreUtilities.DIRECTED_KEY, true);
            }
        }
        
        if (obj.containsKey("dst_ref"))
        {
            JSONObject o1 = bundle.get((String)obj.get("src_ref"));
            if (o1 != null)
            {
                result.add();
                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, label);
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);

                result.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, (String)o1.get("name"));
                result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, getVertexType((String)o1.get("type")));

                result.set(GraphRecordStoreUtilities.TRANSACTION + GraphRecordStoreUtilities.DIRECTED_KEY, true);
            }
        }
                
        if (obj.containsKey("body_multipart"))
        {
            for (Object o : (JSONArray)obj.get("body_multipart"))
            {
                JSONObject o1 = bundle.get((String)o);
                if (o1 != null)
                {
                    result.add();
                    result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, label);
                    result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                    drawObject(o1, GraphRecordStoreUtilities.DESTINATION, bundle, result, showReferences);
                }
            }
        }
        if (obj.containsKey("belongs_to_refs"))
        {
            drawBasicLinkedNodes(label, type, "belongs_to_refs", "Belongs To", obj, bundle, result);
        }        
                
        if (obj.containsKey("resolves_to_refs"))
        {
            drawBasicLinkedNodes(label, type, "resolves_to_refs", "Resolves To", obj, bundle, result);
        }
        
        if (obj.containsKey("raw_email_ref"))
        {
            drawBasicLinkedNode(label, type, "raw_email_ref", "Raw Email", obj, bundle, result); 
        }
        
        if (obj.containsKey("parent_directory_ref"))
        {
            drawBasicLinkedNode(label, type, "parent_directory_ref", "Parent Directory", obj, bundle, result); 
        }
        
        if (obj.containsKey("content_ref"))
        {
            drawBasicLinkedNode(label, type, "content_ref", "Content", obj, bundle, result); 
        }
        
        if (obj.containsKey("contains_refs"))
        {
            drawBasicLinkedNodes(label, type, "contains_refs", "Contains", obj, bundle, result); 
        }
        
        if (obj.containsKey("hashes"))
        {
            for (Object o : ((JSONObject)obj.get("hashes")).keySet() )
            {
                JSONObject o1 = (JSONObject)o;
                for (Object key : o1.keySet())
                if (key != null)
                {
                    SchemaVertexType hashType = AnalyticConcept.VertexType.HASH;
                    switch((String)o1.get(key))
                    {
                        case "MD5":
                            hashType = AnalyticConcept.VertexType.MD5;
                            break;
                        case "SHA-1":
                            hashType = AnalyticConcept.VertexType.SHA1;
                            break;
                        case "SHA-256":
                            hashType = AnalyticConcept.VertexType.SHA256;
                            break;
                        case "SHA-512":
                            hashType = CyberConcept.VertexType.SHA512;
                            break;
                    }
                    result.add();
                    
                    result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, label);
                    result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                    
                    result.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, (String)o1.get(key));
                    result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, hashType);
                    
                }
            }
        } 
        
        if (obj.containsKey("external_references") && showReferences)
        {
            JSONArray extRefs = (JSONArray)obj.get("external_references");
            for (Object r : extRefs)
            {
                JSONObject ref = (JSONObject)r;
                result.add();
                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, label);
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, type);
                
                String extLabel = (String)ref.get("source_name");

                result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.SOURCE, (String)ref.get("source_name"));
                result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, AnalyticConcept.VertexType.DOCUMENT);
                
                if (ref.containsKey("description"))
                {
                    result.set(GraphRecordStoreUtilities.DESTINATION + ContentConcept.VertexAttribute.DESCRIPTION, (String)ref.get("description"));
                }
                if (ref.containsKey("url"))
                {
                    result.set(GraphRecordStoreUtilities.DESTINATION + ContentConcept.VertexAttribute.URL , ((String)ref.get("url")).trim());
                    extLabel = (String)ref.get("url");
                }
                if (ref.containsKey("external_id"))
                {
                    result.set(GraphRecordStoreUtilities.DESTINATION + ContentConcept.VertexAttribute.URL , (String)ref.get("external_id"));
                    extLabel = (String)ref.get("external_id");
                }
                
                result.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, extLabel);
                result.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, AnalyticConcept.TransactionType.REFERENCED);
                
                
            }
        }
        
        if (obj.containsKey("object_refs"))
        {
            drawBasicLinkedNodes(label, type, "object_refs", null, obj, bundle, result); 
        }
        if (obj.containsKey("from_ref"))
        {
            drawBasicLinkedNode(label, type, "from_ref", "From", obj, bundle, result); 
        }
        if (obj.containsKey("sender_ref"))
        {
            drawBasicLinkedNode(label, type, "sender_ref", "Sender", obj, bundle, result); 
        }
        if (obj.containsKey("object_ref"))
        {
            drawBasicLinkedNode(label, type, "object_ref", "Object", obj, bundle, result); 
        }
        if (obj.containsKey("to_refs"))
        {
            drawBasicLinkedNodes(label, type, "to_refs", "To", obj, bundle, result); 
        }
        
        if (obj.containsKey("cc_refs"))
        {
            drawBasicLinkedNodes(label, type, "cc_refs", "CC", obj, bundle, result); 
        }
        
        if (obj.containsKey("bcc_refs"))
        {
            drawBasicLinkedNodes(label, type, "bcc_refs", "BCC", obj, bundle, result); 
        }
        
        if (obj.containsKey("sighting_of_ref"))
        {
            drawBasicLinkedNode(label, type, "sighting_of_ref", "Sighting", obj, bundle, result); 
        }
        if (obj.containsKey("created_by_ref"))
        {
            drawBasicLinkedNode(label, type, "created_by_ref", "Created By", obj, bundle, result); 
        }
        
        if (obj.containsKey("observed_data_refs"))
        {
            drawBasicLinkedNodes(label, type, "observed_data_refs", "Observed Data", obj, bundle, result); 
        }
        
        if (obj.containsKey("where_sighted_refs"))
        {
            drawBasicLinkedNodes(label, type, "where_sighted_refs", "Where Sighted", obj, bundle, result); 
        }
        
        if (obj.containsKey("operating_system_refs"))
        {
            drawBasicLinkedNodes(label, type, "operating_system_refs", "Executable on", obj, bundle, result);   
        }
        
        if (obj.containsKey("sample_refs"))
        {
            drawBasicLinkedNodes(label, type, "sample_refs", "Sample", obj, bundle, result);
        }
        if (obj.containsKey("host_vm_ref"))
        {
            drawBasicLinkedNode(label, type, "host_vm_refs", "Host VM", obj, bundle, result);
        }
        if (obj.containsKey("operating_system_ref"))
        {
            drawBasicLinkedNode(label, type, "operating_system_ref", "Operating System", obj, bundle, result);
        }
        if (obj.containsKey("installed_software_refs"))
        {
            drawBasicLinkedNodes(label, type, "installed_software_refs", "Installed Software", obj, bundle, result);
        }
        if (obj.containsKey("analysis_sco_refs"))
        {
            drawBasicLinkedNodes(label, type, "analysis_sco_refs", null, obj, bundle, result);
        }
        if (obj.containsKey("sample_ref"))
        {
            drawBasicLinkedNode(label, type, "sample_ref", "Sample", obj, bundle, result);
        }
        
    }
    
    private void drawBasicLinkedNode(String parentLabel, String parentType, String key, String transactionName, JSONObject obj, HashMap<String, JSONObject> bundle, RecordStore result)
    {
        JSONObject o1 = bundle.get((String)obj.get(key));
        if (o1 != null)
        {
            result.add();
            result.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, parentLabel);
            result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, parentType);

            result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, (String)o1.get("name"));
            result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, getVertexType((String)o1.get("type")));
            if (transactionName != null)
            {
                result.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, transactionName);
            }
        }
    }
    
    private void drawBasicLinkedNodes(String parentLabel, String parentType, String key, String transactionName, JSONObject obj, HashMap<String, JSONObject> bundle, RecordStore result)
    {
        for (Object o : (JSONArray)obj.get("where_sighted_refs"))
        {
            JSONObject o1 = bundle.get((String)o);
            if (o1 != null)
            {
                result.add();
                result.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, parentLabel);
                result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, parentType);

                result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, (String)o1.get("name"));
                result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, getVertexType((String)o1.get("type")));
                if (transactionName != null)
                {
                    result.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, transactionName);
                }
            }
        }
    }
    
    private void drawRelationship(JSONObject obj, HashMap<String, JSONObject> bundle, RecordStore result)
    {
        
        String srcId = (String)obj.get("source_ref");
        String dstId = (String)obj.get("target_ref");
        
        JSONObject src = bundle.get(srcId);
        JSONObject dest = bundle.get(dstId);
        
        String srcLabel = (String)src.get("name");
        String srcType = (String)src.get("type");

        result.add();
        result.set(GraphRecordStoreUtilities.SOURCE + VisualConcept.VertexAttribute.IDENTIFIER, srcLabel);
        result.set(GraphRecordStoreUtilities.SOURCE + AnalyticConcept.VertexAttribute.TYPE, getVertexType(srcType));
        
        if (dest != null)
        {
            String dstLabel = (String)dest.get("name");
            String dstType = (String)dest.get("type");
            
            result.set(GraphRecordStoreUtilities.DESTINATION + VisualConcept.VertexAttribute.IDENTIFIER, dstLabel);
            result.set(GraphRecordStoreUtilities.DESTINATION + AnalyticConcept.VertexAttribute.TYPE, getVertexType(dstType));
            
            
            result.set(GraphRecordStoreUtilities.TRANSACTION + VisualConcept.TransactionAttribute.IDENTIFIER, obj.get("id"));
            result.set(GraphRecordStoreUtilities.TRANSACTION + AnalyticConcept.TransactionAttribute.TYPE, obj.get("relationship_type"));
            
            if (obj.containsKey("description"))
            {
                result.set(GraphRecordStoreUtilities.TRANSACTION + ContentConcept.VertexAttribute.DESCRIPTION, (String)obj.get("description"));
            }   
            if (obj.containsKey("start_time"))
            {
                result.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.VertexAttribute.START_TIME, TemporalFormatting.completeZonedDateTimeString((String)obj.get("start_time")) );
            }
            if (obj.containsKey("stop_time"))
            {
                result.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.VertexAttribute.END_TIME, TemporalFormatting.completeZonedDateTimeString((String)obj.get("stop_time")) );
            }
            if (obj.containsKey("first_seen"))
            {
                result.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.VertexAttribute.FIRST_SEEN, TemporalFormatting.completeZonedDateTimeString((String)obj.get("first_seen")) );
            }
            if (obj.containsKey("last_seen"))
            {
                result.set(GraphRecordStoreUtilities.TRANSACTION + TemporalConcept.VertexAttribute.LAST_SEEN, TemporalFormatting.completeZonedDateTimeString((String)obj.get("last_seen")) );
            }
            if (obj.containsKey("count"))
            {
                result.set(GraphRecordStoreUtilities.TRANSACTION + "Count", (Integer)obj.get("number_observed") );
            }
        }
    }

    private void drawBundle(HashMap<String, JSONObject> bundle, RecordStore result, PluginInteraction interaction, boolean showReferences)
    {
        // first draw objects
        for (String key : bundle.keySet())
        {
            JSONObject o = bundle.get(key);
            if (isObject(o))
            {
                drawObject(o, GraphRecordStoreUtilities.SOURCE,  bundle, result, showReferences);
            }
            else
            {
                drawRelationship(o, bundle, result);
            }
        }
        
    }


    @Override
    protected RecordStore query(RecordStore query, PluginInteraction interaction, PluginParameters parameters) throws InterruptedException, PluginException {
        final RecordStore results = new GraphRecordStore();
        
        //get parsers from object.
        final Map<String, PluginParameter<?>> params = parameters.getParameters();

        final String filepath =  parameters.getParameters().get(FILEPATH_PARAMETER_ID).getStringValue();
        final boolean showReferences =  parameters.getParameters().get(SHOW_REFERENCES_PARAMETER_ID).getBooleanValue();
        
        JSONParser p = new JSONParser();
        try {
            JSONObject root = (JSONObject)p.parse(new FileReader(new File(filepath)));
            
            // check type is bundle.
            if (!root.containsKey("type") || 
                    !((String)root.get("type")).equalsIgnoreCase("bundle"))
            {
                interaction.notify(PluginNotificationLevel.FATAL, "File does not appear to be of type bundle.");
                return results;
            }
            
            // check version
            if (!root.containsKey("spec_version") || 
                    !((String)root.get("spec_version")).startsWith("2."))
            {
                interaction.notify(PluginNotificationLevel.FATAL, "File spec_version is not 2.x");
                return results;
            }
            
            HashMap<String, JSONObject> bundle = new HashMap<>();
            
            for (Object o : (JSONArray)root.getOrDefault("objects", new JSONArray()))
            {
                JSONObject o1 = (JSONObject)o;
                String key = (String)o1.get("id");
                bundle.put(key, o1);
            }
            
            drawBundle(bundle, results, interaction, showReferences);
            
        } catch (FileNotFoundException ex) {
            Exceptions.printStackTrace(ex);
        } catch (IOException ex) {
            Exceptions.printStackTrace(ex);
        } catch (ParseException ex) {
            Exceptions.printStackTrace(ex);
        }
        
        return results;
    }
 
}
