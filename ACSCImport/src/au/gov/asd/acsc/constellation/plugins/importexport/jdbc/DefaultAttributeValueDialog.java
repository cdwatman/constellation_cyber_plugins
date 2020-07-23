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

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.GridPane;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

public class DefaultAttributeValueDialog extends Stage {

    private final TextField labelText;
    private String defaultValue = null;

    public DefaultAttributeValueDialog(Stage owner, String attributeName, String initialValue) {

        defaultValue = initialValue;

        initStyle(StageStyle.UTILITY);
        initModality(Modality.WINDOW_MODAL);
        initOwner(owner);

        setTitle("Set Default Value: " + attributeName);

        BorderPane root = new BorderPane();
        root.setStyle("-fx-background-color: #DDDDDD;");
        Scene scene = new Scene(root);
        setScene(scene);

        GridPane fieldPane = new GridPane();
        fieldPane.setHgap(5);
        fieldPane.setVgap(5);
        fieldPane.setPadding(new Insets(10));
        root.setCenter(fieldPane);

        Label labelLabel = new Label("Label:");
        GridPane.setConstraints(labelLabel, 0, 1);
        fieldPane.getChildren().add(labelLabel);

        labelText = new TextField();
        if (defaultValue == null) {
            labelText.setPromptText("Enter attribute default value");
        } else {
            labelText.setText(defaultValue);
        }
        labelText.setPrefSize(200, 30);
        GridPane.setConstraints(labelText, 1, 1);
        fieldPane.getChildren().add(labelText);
        labelText.requestFocus();

        FlowPane buttonPane = new FlowPane();
        buttonPane.setAlignment(Pos.BOTTOM_RIGHT);
        buttonPane.setPadding(new Insets(5));
        buttonPane.setHgap(5);
        root.setBottom(buttonPane);

        Button okButton = new Button("Ok");
        okButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                defaultValue = labelText.getText();
                DefaultAttributeValueDialog.this.hide();
            }
        });
        buttonPane.getChildren().add(okButton);

        Button cancelButton = new Button("Cancel");
        cancelButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                DefaultAttributeValueDialog.this.hide();
            }
        });
        buttonPane.getChildren().add(cancelButton);

        Button clearButton = new Button("Clear");
        clearButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                defaultValue = null;
                DefaultAttributeValueDialog.this.hide();
            }
        });
        buttonPane.getChildren().add(clearButton);
    }

    public String getDefaultValue() {
        return defaultValue;
    }
}