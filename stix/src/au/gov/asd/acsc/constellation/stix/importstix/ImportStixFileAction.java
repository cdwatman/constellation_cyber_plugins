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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javafx.application.Platform;
import org.openide.awt.ActionID;
import org.openide.awt.ActionReference;
import org.openide.awt.ActionReferences;
import org.openide.awt.ActionRegistration;
import org.openide.util.NbBundle.Messages;

@ActionID(
        category = "File",
        id = "au.gov.asd.acsc.constellation.stix.importstix.ImportStixFileAction")
@ActionRegistration(
        displayName = "#CTL_ImportStixFileAction", iconBase = "au/gov/asd/acsc/constellation/schema/cyberschema/icons/oasis_icon.png")
@ActionReferences({
    @ActionReference(path = "Menu/File/Import", position = 0),
    @ActionReference(path = "Toolbars/File", position = 0)
})
@Messages("CTL_ImportStixFileAction=Import STIX...")
public final class ImportStixFileAction implements ActionListener {

    @Override
    public void actionPerformed(final ActionEvent e) {
        Platform.runLater(() -> {
            final StixFileImporterStage stage = new StixFileImporterStage();
            stage.show();
            
        });
    }
}
