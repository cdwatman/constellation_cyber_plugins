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

import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.SQLException;
import java.util.Properties;
import javafx.scene.control.Alert;
import javafx.scene.control.TextArea;

public class JDBCConnection {
    private String _connectionName;
    private JDBCDriver _driver;
    private String _connectionString;
    
    public JDBCConnection(String connectionName, JDBCDriver driver,  String connectionString)
    {
        this._connectionName = connectionName;
        this._driver = driver;
        this._connectionString = connectionString;
    }
    
    public Connection getConnection(String user, String password) throws MalformedURLException, ClassNotFoundException, SQLException, NoSuchMethodException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
    {
        Driver driver = _driver.getDriver();

        final Properties props = new Properties();
        props.put("user", user);
        props.put("password", password);
        Connection a = driver.connect(_connectionString, props);   
        return a;
    }

    public boolean testConnection(String user, String password, boolean showError)
    {
        try (Connection conn = getConnection(user, password))
        {
            if (conn ==null)
            {
                Alert a = new Alert(Alert.AlertType.ERROR);
                a.setTitle("Connection Failed");
                TextArea b = new TextArea();
                b.setEditable(false);
                b.setWrapText(true);
                b.setText("Testing of the connection failed, please recheck your connection string settings.");
                a.getDialogPane().setContent(b);
                a.showAndWait();
                return false;
            }
        } catch (MalformedURLException | ClassNotFoundException | SQLException | NoSuchMethodException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
            if (showError)
            {
                Alert a = new Alert(Alert.AlertType.ERROR);
                a.setTitle("Connection Failed");
                a.setContentText("Testing of the connection failed, please recheck your settings.");
                TextArea b = new TextArea();
                b.setEditable(false);
                b.setWrapText(true);
                b.setText(ex.getMessage());
                a.getDialogPane().setContent(b);
                a.showAndWait();
            }
            return false;
        }
        return true;   
    }

    public JDBCDriver getDriver() {
        return _driver;
    }

    public void setDriver(JDBCDriver _driver) {
        this._driver = _driver;
    }

    public String getConnectionString() {
        return _connectionString;
    }

    public void setConnectionString(String _connectionString) {
        this._connectionString = _connectionString;
    }

    public String getConnectionName() {
        return _connectionName;
    }

    public void setConnectionName(String _connectionName) {
        this._connectionName = _connectionName;
    }
    
    @Override
    public String toString()
    {
       return _connectionName;
    }
}
