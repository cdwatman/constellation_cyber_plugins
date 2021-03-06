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

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.TextArea;
import org.openide.util.Exceptions;

public class JDBCConnectionManager {
    
    static JDBCConnectionManager  __instance__ = null;
    
    private HashMap<String, JDBCConnection> __connections = new HashMap<>();
    private SQLiteDBManager sql;
    private File driversDir;
    
    private JDBCConnectionManager()
    {
        //load drivers from db
        File basePath = new File(String.format("%s%s.CONSTELLATION%sJDBCImport%s", System.getProperty("user.home"), File.separator, File.separator, File.separator));
        if (!basePath.exists())
        {
            basePath.mkdirs();
        }
        driversDir = new File(basePath.getAbsolutePath() + File.separator + "jars");
        if (!driversDir.exists())
        {
            driversDir.mkdirs();
        }
        
        sql = SQLiteDBManager.getInstance();
        
        JDBCDriverManager dm = JDBCDriverManager.getInstance();
        try (final Connection connection = sql.getConnection()) {

            try (final PreparedStatement statement = connection.prepareStatement("SELECT * from connection")) {
                try (final ResultSet connections = statement.executeQuery()) {
                    while (connections.next()) {
                        JDBCDriver driver = dm.getDriver(connections.getString("driver_name"));
                        if (driver != null)
                        {
                            JDBCConnection d = new JDBCConnection(connections.getString("name"), driver, connections.getString("connection_string"));
                            __connections.put(d.getConnectionName(), d);
                        }
                    }
                }
            }
        } catch (SQLException ex) {
            Exceptions.printStackTrace(ex);
        } catch (IOException ex) {
            Exceptions.printStackTrace(ex);
        }
    }

    
    public ArrayList<JDBCConnection> getConnections()
    {
        return new ArrayList(__connections.values());
    }
    
    public boolean testConnection(String connectionName, JDBCDriver driver, String username, String password, String connectionString)
    {
        JDBCConnection conn = new JDBCConnection(connectionName, driver, connectionString);
        return conn.testConnection(username, password, true);
    }
    
    public boolean addConnection(String connectionName, JDBCDriver driver, String username, String password, String connectionString) 
    {
        JDBCConnection conn = new JDBCConnection(connectionName, driver, connectionString);
        if (testConnection(connectionName, driver, username, password, connectionString))
        {
            try (final Connection connection = sql.getConnection()) {
                try (final PreparedStatement statement = connection.prepareStatement("insert into connection (name, driver_name, connection_string) values (?, ?, ?)")) {
                    statement.setString(1, connectionName);
                    statement.setString(2, driver.getName());
                    statement.setString(3, connectionString);
                    statement.executeUpdate();
                }
                __connections.put(connectionName, new JDBCConnection(connectionName, driver, connectionString));

            } catch (IOException | SQLException ex) {
                Alert a = new Alert(AlertType.ERROR);
                a.setTitle("Connection add failed");
                a.setContentText("Failed to add the connection to the database.");
                TextArea ta = new TextArea(ex.getMessage());
                ta.setEditable(false);
                ta.setWrapText(true);
                a.getDialogPane().setExpandableContent(ta);

                a.showAndWait();
                return false;
            }
            return true;
        }
        else
        {
            return false;
        }
    }
    
    public void deleteConnection(String name)
    {
        JDBCConnection d = __connections.get(name);
        if (d != null)
        {
            __connections.remove(name);
        }
        try (final Connection connection = sql.getConnection()) {
            try (final PreparedStatement statement = connection.prepareStatement("delete from connection where name=?")) {
                statement.setString(1, name);
                statement.executeUpdate();
            }
        } catch (SQLException | IOException ex ) {
            Alert a = new Alert(AlertType.ERROR);
            a.setTitle("Connection delete failed");
            a.setContentText("Failed to delete the connection from the database.");
            TextArea ta = new TextArea(ex.getMessage());
            ta.setEditable(false);
            ta.setWrapText(true);
            a.getDialogPane().setExpandableContent(ta);
            
            a.showAndWait();
        } 
    }
    
    public static JDBCConnectionManager getInstance()
    {
        if (__instance__ == null)
        {
            __instance__ = new JDBCConnectionManager();
        }
        return __instance__;
    }
    
    
    
}
