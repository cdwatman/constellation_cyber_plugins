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

import au.gov.asd.acsc.constellation.plugins.importexport.jdbc.EasyGridPane;
import au.gov.asd.acsc.constellation.plugins.importexport.jdbc.GraphDestination;
import au.gov.asd.acsc.constellation.plugins.importexport.jdbc.ImportDestination;
import au.gov.asd.acsc.constellation.plugins.importexport.jdbc.SchemaDestination;
import au.gov.asd.tac.constellation.graph.Graph;
import au.gov.asd.tac.constellation.graph.file.opener.GraphOpener;
import au.gov.asd.tac.constellation.graph.manager.GraphManager;
import au.gov.asd.tac.constellation.graph.manager.GraphManagerListener;
import au.gov.asd.tac.constellation.graph.schema.SchemaFactory;
import au.gov.asd.tac.constellation.graph.schema.SchemaFactoryUtilities;
import au.gov.asd.tac.constellation.plugins.PluginExecutor;
import au.gov.asd.tac.constellation.utilities.color.ConstellationColor;
import au.gov.asd.tac.constellation.utilities.font.FontUtilities;
import au.gov.asd.tac.constellation.utilities.icon.UserInterfaceIconProvider;
import au.gov.asd.tac.constellation.utilities.javafx.JavafxStyleManager;
import java.io.File;
import java.util.Map;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.HPos;
import javafx.geometry.Insets;
import javafx.geometry.Rectangle2D;
import javafx.geometry.VPos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Screen;
import javafx.stage.Stage;
import org.netbeans.api.annotations.common.StaticResource;
import org.openide.util.HelpCtx;


public class StixFileImporterStage extends Stage {

    private static final String HELP_CTX = StixFileImporterStage.class.getName();

    private static final Image HELP_IMAGE = UserInterfaceIconProvider.HELP.buildImage(16, ConstellationColor.AZURE.getJavaColor());

    public StixFileImporterStage() {
        final BorderPane root = new BorderPane();
        final EasyGridPane gridPane = new EasyGridPane();
        gridPane.setPadding(new Insets(5));
        gridPane.setHgap(5);
        gridPane.setVgap(5);
        gridPane.addColumnConstraint(true, HPos.LEFT, Priority.NEVER, Double.MAX_VALUE, 100, GridPane.USE_COMPUTED_SIZE, -1);
        gridPane.addColumnConstraint(true, HPos.LEFT, Priority.ALWAYS, Double.MAX_VALUE, 100, GridPane.USE_COMPUTED_SIZE, -1);
        gridPane.addColumnConstraint(true, HPos.LEFT, Priority.NEVER, Double.MAX_VALUE, 100, GridPane.USE_COMPUTED_SIZE, -1);
        gridPane.addRowConstraint(true, VPos.TOP, Priority.ALWAYS, Double.MAX_VALUE, 0, GridPane.USE_COMPUTED_SIZE, -1);
        gridPane.addRowConstraint(true, VPos.TOP, Priority.ALWAYS, Double.MAX_VALUE, 0, GridPane.USE_COMPUTED_SIZE, -1);
        gridPane.addRowConstraint(true, VPos.BOTTOM, Priority.ALWAYS, Double.MAX_VALUE, 0, GridPane.USE_COMPUTED_SIZE, -1);

        ObservableList<ImportDestination<?>> destinations = FXCollections.observableArrayList();

        Map<String, Graph> graphs = GraphManager.getDefault().getAllGraphs();
        Graph activeGraph = GraphManager.getDefault().getActiveGraph();
        ImportDestination<?> defaultDestination = null;
        for (Graph graph : graphs.values()) {
            GraphDestination destination = new GraphDestination(graph);
            destinations.add(destination);
            if (graph == activeGraph) {
                defaultDestination = destination;
            }
        }

        Map<String, SchemaFactory> schemaFactories = SchemaFactoryUtilities.getSchemaFactories();
        for (SchemaFactory schemaFactory : schemaFactories.values()) {
            SchemaDestination destination = new SchemaDestination(schemaFactory);
            destinations.add(destination);
            if (defaultDestination == null) {
                defaultDestination = destination;
            }
        }

        final ComboBox<ImportDestination<?>> graphComboBox = new ComboBox<>();
        graphComboBox.setItems(destinations);
        
        graphComboBox.getSelectionModel().select(defaultDestination);
        
        gridPane.add(new Label("STIX2 File"),0,0);
        TextField pathTxt = new TextField();
        gridPane.add(pathTxt, 1,0);
        Button selectBtn = new Button("..");
        selectBtn.setOnAction(e -> {
            
            FileChooser c = new FileChooser();
            c.getExtensionFilters().add(new ExtensionFilter("STIX2","*.json"));
            c.setTitle("Select STIX2 File");
            if (!pathTxt.getText().isBlank())
            {
                c.setInitialFileName(pathTxt.getText());
            }
            File f = c.showOpenDialog(this);
            if (f != null)
            {
                if (f.exists() && f.canRead())
                {
                    pathTxt.setText(f.getAbsolutePath());
                }
            }
        });
        gridPane.add(selectBtn, 2, 0);
        
        gridPane.add(new Label("Destination"),0,1);
        gridPane.add(graphComboBox, 1, 1);

        CheckBox showReferencesChk = new CheckBox();
        
        gridPane.add(new Label("Show references"),0,2);
        gridPane.add(showReferencesChk, 1, 2);
        
        StixFileImporterStage s = this;
        
        Button addBtn = new Button("Parse");
        addBtn.setOnAction(new EventHandler<>() {
            @Override
            public void handle(ActionEvent event) {
                ImportDestination<?> currentDestination = graphComboBox.getValue();
        
                final Graph importGraph = currentDestination.getGraph();

                String filepath = pathTxt.getText();
                boolean showReferences = showReferencesChk.isSelected();
                
                if (filepath.isBlank())
                {
                    return;
                }
                
                if (currentDestination instanceof SchemaDestination) {
                    GraphManager.getDefault().addGraphManagerListener(new GraphManagerListener() {
                        boolean opened = false;

                        @Override
                        public void graphOpened(Graph graph) {
                        }

                        @Override
                        public void graphClosed(Graph graph) {
                        }

                        @Override
                        public synchronized void newActiveGraph(Graph graph) {
                            if (graph == importGraph && !opened) {
                                opened = true;
                                GraphManager.getDefault().removeGraphManagerListener(this);

                                PluginExecutor.startWith(StixFileImporterPlugin.class.getName(), false)
                                        .set(StixFileImporterPlugin.FILEPATH_PARAMETER_ID, filepath)
                                        .set(StixFileImporterPlugin.SHOW_REFERENCES_PARAMETER_ID, showReferences)
                                        .executeWriteLater(importGraph);
                                Platform.runLater(new Runnable(){
                                    @Override
                                    public void run() {
                                        s.close();
                                    }
                                });

                            }
                            
                        }

                    });
                    GraphOpener.getDefault().openGraph(importGraph, "graph");
                } else {
                    PluginExecutor.startWith(StixFileImporterPlugin.class.getName(), false)
                        .set(StixFileImporterPlugin.FILEPATH_PARAMETER_ID, filepath)
                        .set(StixFileImporterPlugin.SHOW_REFERENCES_PARAMETER_ID, showReferences)
                        .executeWriteLater(importGraph);
                }
            }
        
        });
            
        gridPane.add(addBtn,2,4);
        
        
        
        final Rectangle2D visualBounds = Screen.getPrimary().getVisualBounds();
        final double screenHeight = visualBounds.getHeight();
        
        final ScrollPane sp = new ScrollPane(gridPane);
        sp.setFitToWidth(true);

        sp.setFitToHeight(true);
        sp.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        sp.setVbarPolicy(ScrollPane.ScrollBarPolicy.AS_NEEDED);
        root.setCenter(sp);
        root.setCenter(new VBox(sp));

        final Scene scene = new Scene(root);
        scene.getStylesheets().add(JavafxStyleManager.getMainStyleSheet());
        scene.rootProperty().get().setStyle(String.format("-fx-font-size:%d;", FontUtilities.getOutputFontSize()));
        scene.setFill(Color.WHITESMOKE);
        scene.setOnKeyPressed(event -> {
            final KeyCode c = event.getCode();
            if (c == KeyCode.F1) {
                new HelpCtx(HELP_CTX).display();
            }
        });

        setScene(scene);
        setTitle("STIX Importer");
        //getIcons().add(new Image(STIX_IMPORTER_ICON_PATH));
        StixFileImporterStage.this.centerOnScreen();
    }


}
