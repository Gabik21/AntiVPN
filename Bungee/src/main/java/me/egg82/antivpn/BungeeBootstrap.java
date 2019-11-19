package me.egg82.antivpn;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Collections;
import java.util.UUID;
import java.util.logging.Level;
import me.egg82.antivpn.services.GameAnalyticsErrorHandler;
import me.egg82.antivpn.utils.JarUtil;
import me.egg82.antivpn.utils.LogUtil;
import me.egg82.antivpn.utils.ValidationUtil;
import me.lucko.jarrelocator.Relocation;
import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.plugin.Plugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BungeeBootstrap extends Plugin {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private AntiVPN concrete;
    private final String externalPath = "me{}egg82{}antivpn{}external";

    @Override
    public void onLoad() {
        try {
            loadJars(new File(getDataFolder(), "external"), (URLClassLoader) getClass().getClassLoader());
        } catch (ClassCastException | IOException | IllegalAccessException | InvocationTargetException ex) {
            logger.error(ex.getMessage(), ex);
            throw new RuntimeException("Could not load required deps.");
        }

        concrete = new AntiVPN(this);

    }

    @Override
    public void onEnable() {
        GameAnalyticsErrorHandler.open(getID(), getDescription().getVersion(), getProxy().getVersion());
        concrete.onEnable();
    }

    @Override
    public void onDisable() {
        concrete.onDisable();
        GameAnalyticsErrorHandler.close();
    }

    private void loadJars(File jarsFolder, URLClassLoader classLoader) throws IOException, IllegalAccessException, InvocationTargetException {
        if (jarsFolder.exists() && !jarsFolder.isDirectory()) {
            Files.delete(jarsFolder.toPath());
        }
        if (!jarsFolder.exists()) {
            if (!jarsFolder.mkdirs()) {
                throw new IOException("Could not create parent directory structure.");
            }
        }

        getProxy().getLogger().log(Level.INFO, LogUtil.getHeading() + ChatColor.YELLOW + "Loading dep " + ChatColor.WHITE + "Caffeine");
        JarUtil.loadJar("http://central.maven.org/maven2/com/github/ben-manes/caffeine/caffeine/2.6.2/caffeine-2.6.2.jar",
                new File(jarsFolder, "caffeine-2.6.2.jar"),
                new File(jarsFolder, "caffeine-2.6.2-relocated.jar"),
                classLoader,
                Collections.singletonList(new Relocation(parse("com{}github{}benmanes{}caffeine"), parse(externalPath + "{}com{}github{}benmanes{}caffeine"))));

        getProxy().getLogger().log(Level.INFO, LogUtil.getHeading() + ChatColor.YELLOW + "Loading dep " + ChatColor.WHITE + "RabbitMQ");
        JarUtil.loadJar("http://central.maven.org/maven2/com/rabbitmq/amqp-client/5.5.0/amqp-client-5.5.0.jar",
                new File(jarsFolder, "amqp-client-5.5.0.jar"),
                classLoader);

        getProxy().getLogger().log(Level.INFO, LogUtil.getHeading() + ChatColor.YELLOW + "Loading dep " + ChatColor.WHITE + "HikariCP");
        JarUtil.loadJar("http://central.maven.org/maven2/com/zaxxer/HikariCP/3.2.0/HikariCP-3.2.0.jar",
                new File(jarsFolder, "HikariCP-3.2.0.jar"),
                new File(jarsFolder, "HikariCP-3.2.0-relocated.jar"),
                classLoader,
                Collections.singletonList(new Relocation(parse("com{}zaxxer{}hikari"), parse(externalPath + "{}com{}zaxxer{}hikari"))));

        getProxy().getLogger().log(Level.INFO, LogUtil.getHeading() + ChatColor.YELLOW + "Loading dep " + ChatColor.WHITE + "Redis");
        JarUtil.loadJar("http://central.maven.org/maven2/redis/clients/jedis/2.9.0/jedis-2.9.0.jar",
                new File(jarsFolder, "jedis-2.9.0.jar"),
                new File(jarsFolder, "jedis-2.9.0-relocated.jar"),
                classLoader,
                Collections.singletonList(new Relocation(parse("redis{}clients"), parse(externalPath + "{}redis{}clients"))));

        getProxy().getLogger().log(Level.INFO, LogUtil.getHeading() + ChatColor.YELLOW + "Loading dep " + ChatColor.WHITE + "Javassist");
        JarUtil.loadJar("http://central.maven.org/maven2/org/javassist/javassist/3.23.1-GA/javassist-3.23.1-GA.jar",
                new File(jarsFolder, getJavassistString() + "-3.23.1-GA.jar"),
                classLoader);

        getProxy().getLogger().log(Level.INFO, LogUtil.getHeading() + ChatColor.YELLOW + "Loading dep " + ChatColor.WHITE + "Apache Collections");
        JarUtil.loadJar("http://central.maven.org/maven2/commons-collections/commons-collections/3.2.2/commons-collections-3.2.2.jar",
                new File(jarsFolder, "commons-collections-3.2.2.jar"),
                new File(jarsFolder, "commons-collections-3.2.2-relocated.jar"),
                classLoader,
                Collections.singletonList(new Relocation(parse("org{}apache{}commons{}collections"), parse(externalPath + "{}org{}apache{}commons{}collections"))));

        getProxy().getLogger().log(Level.INFO, LogUtil.getHeading() + ChatColor.YELLOW + "Loading dep " + ChatColor.WHITE + "Apache Net Utils");
        JarUtil.loadJar("http://central.maven.org/maven2/commons-net/commons-net/3.6/commons-net-3.6.jar",
                new File(jarsFolder, "commons-net-3.6.jar"),
                new File(jarsFolder, "commons-net-3.6-relocated.jar"),
                classLoader,
                Collections.singletonList(new Relocation(parse("org{}apache{}commons{}net"), parse(externalPath + "{}org{}apache{}commons{}net"))));

        getProxy().getLogger().log(Level.INFO, LogUtil.getHeading() + ChatColor.YELLOW + "Loading dep " + ChatColor.WHITE + "Apache Lang3");
        JarUtil.loadJar("http://central.maven.org/maven2/org/apache/commons/commons-lang3/3.8.1/commons-lang3-3.8.1.jar",
                new File(jarsFolder, "commons-lang3-3.8.1.jar"),
                new File(jarsFolder, "commons-lang3-3.8.1-relocated.jar"),
                classLoader,
                Collections.singletonList(new Relocation(parse("org{}apache{}commons{}lang3"), parse(externalPath + "{}org{}apache{}commons{}lang3"))));

        try {
            Class.forName("org.reflections.Reflections", false, classLoader);
        } catch (ClassNotFoundException ignored) {
            // 0.9.10 for 1.11 compatibility
            getProxy().getLogger().log(Level.INFO, LogUtil.getHeading() + ChatColor.YELLOW + "Loading dep " + ChatColor.WHITE + "Reflections");
            JarUtil.loadJar("http://central.maven.org/maven2/org/reflections/reflections/0.9.10/reflections-0.9.10.jar",
                    new File(jarsFolder, "reflections-0.9.10.jar"),
                    classLoader);
        }

        try {
            Class.forName("org.sqlite.JDBC", false, classLoader);
        } catch (ClassNotFoundException ignored) {
            getProxy().getLogger().log(Level.INFO, LogUtil.getHeading() + ChatColor.YELLOW + "Loading dep " + ChatColor.WHITE + "SQLite");
            JarUtil.loadJar("http://central.maven.org/maven2/org/xerial/sqlite-jdbc/3.25.2/sqlite-jdbc-3.25.2.jar",
                    new File(jarsFolder, "sqlite-jdbc-3.25.2.jar"),
                    classLoader);
        }

        try {
            DriverManager.getDriver("org.sqlite.JDBC");
        } catch (SQLException ignored) {
            try {
                DriverManager.registerDriver((Driver) Class.forName("org.sqlite.JDBC", true, classLoader).newInstance());
            } catch (ClassNotFoundException | InstantiationException | SQLException ex) {
                logger.error(ex.getMessage(), ex);
            }
        }

        try {
            Class.forName("com.mysql.jdbc.Driver", false, classLoader);
        } catch (ClassNotFoundException ignored) {
            getProxy().getLogger().log(Level.INFO, LogUtil.getHeading() + ChatColor.YELLOW + "Loading dep " + ChatColor.WHITE + "MySQL");
            JarUtil.loadJar("http://central.maven.org/maven2/mysql/mysql-connector-java/8.0.13/mysql-connector-java-8.0.13.jar",
                    new File(jarsFolder, "mysql-connector-java-8.0.13.jar"),
                    classLoader);
        }

        try {
            DriverManager.getDriver("com.mysql.jdbc.Driver");
        } catch (SQLException ignored) {
            try {
                DriverManager.registerDriver((Driver) Class.forName("com.mysql.jdbc.Driver", true, classLoader).newInstance());
            } catch (ClassNotFoundException | InstantiationException | SQLException ex) {
                logger.error(ex.getMessage(), ex);
            }
        }
    }

    // Because Maven's relocate is maybe sometimes a bit too powerful ;)
    private String getJavassistString() {
        return new String(new byte[] {'j', 'a', 'v', 'a', 's', 's', 'i', 's', 't'});
    }

    // Because Maven's relocate is maybe sometimes a bit too powerful ;)
    private String parse(String input) {
        return input.replace("{}", ".");
    }

    private UUID getID() {
        String id;
        try {
            id = readID();
        } catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
            return null;
        }

        if (id == null || id.isEmpty() || id.equalsIgnoreCase("unnamed") || id.equalsIgnoreCase("unknown") || id.equalsIgnoreCase("default") || !ValidationUtil.isValidUuid(id)) {
            id = UUID.randomUUID().toString();
            try {
                writeID(id);
            } catch (IOException ex) {
                logger.error(ex.getMessage(), ex);
            }
        }
        return UUID.fromString(id);
    }

    private String readID() throws IOException {
        File config = new File(getProxy().getPluginsFolder().getParent(), "config.yml");
        if (config.exists() && config.isDirectory()) {
            Files.delete(config.toPath());
        }
        if (!config.exists()) {
            if (!config.createNewFile()) {
                throw new IOException("Stats file could not be created.");
            }
        }

        try (FileReader reader = new FileReader(config); BufferedReader in = new BufferedReader(reader)) {
            String line;
            while ((line = in.readLine()) != null) {
                if (line.trim().startsWith("stats:")) {
                    return line.trim().substring(6).trim();
                }
            }
        }

        return null;
    }

    private void writeID(String id) throws IOException {
        File config = new File(getProxy().getPluginsFolder().getParent(), "config.yml");
        if (config.exists() && config.isDirectory()) {
            Files.delete(config.toPath());
        }
        if (!config.exists()) {
            if (!config.createNewFile()) {
                throw new IOException("Stats file could not be created.");
            }
        }

        boolean written = false;
        StringBuilder builder = new StringBuilder();
        try (FileReader reader = new FileReader(config); BufferedReader in = new BufferedReader(reader)) {
            String line;
            while ((line = in.readLine()) != null) {
                if (line.trim().startsWith("stats:")) {
                    written = true;
                    builder.append("stats:" + id).append(System.lineSeparator());
                } else {
                    builder.append(line).append(System.lineSeparator());
                }
            }
        }
        if (!written) {
            builder.append("stats:" + id).append(System.lineSeparator());
        }

        try (FileWriter out = new FileWriter(config)) {
            out.write(builder.toString());
        }
    }
}
