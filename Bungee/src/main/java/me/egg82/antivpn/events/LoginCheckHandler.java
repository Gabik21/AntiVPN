package me.egg82.antivpn.events;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.sql.SQLException;
import java.util.function.Consumer;

import me.egg82.antivpn.AntiVPN;
import me.egg82.antivpn.VPNAPI;
import me.egg82.antivpn.extended.CachedConfigValues;
import me.egg82.antivpn.extended.Configuration;
import me.egg82.antivpn.hooks.PlayerAnalyticsHook;
import me.egg82.antivpn.sql.MySQL;
import me.egg82.antivpn.utils.LogUtil;
import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.event.PostLoginEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.event.EventHandler;
import ninja.egg82.core.SQLQueryResult;
import ninja.egg82.service.ServiceLocator;
import ninja.egg82.service.ServiceNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LoginCheckHandler implements Listener {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final VPNAPI api = VPNAPI.getInstance();

    private final Plugin plugin;

    public LoginCheckHandler(Plugin plugin) {
        this.plugin = plugin;
    }

    @EventHandler
    public void onLogin(LoginEvent event) {
        String ip = getIp(event.getConnection().getAddress());
        if (ip == null || ip.isEmpty()) {
            return;
        }

        Configuration config;
        CachedConfigValues cachedConfig;

        try {
            config = ServiceLocator.get(Configuration.class);
            cachedConfig = ServiceLocator.get(CachedConfigValues.class);
        } catch (InstantiationException | IllegalAccessException | ServiceNotFoundException ex) {
            logger.error(ex.getMessage(), ex);
            return;
        }

        if (!config.getNode("kick", "enabled").getBoolean(true)) {
            if (cachedConfig.getDebug()) {
                logger.info(LogUtil.getHeading() + ChatColor.YELLOW + "Plugin set to API-only. Ignoring " + ChatColor.WHITE + event.getConnection().getName());
            }
            return;
        }

        if (cachedConfig.getIgnoredIps().contains(ip)) {
            return;
        }

        event.registerIntent(plugin);

        ProxyServer.getInstance().getScheduler().runAsync(plugin, () -> {
            try {
                SQLQueryResult query = cachedConfig.getSQL().query("SELECT rank, kills FROM users WHERE uuid = ?", event.getConnection().getUniqueId().toString());

                if (query.getData().length > 0) {
                    if (!query.getData()[0][0].equals("DEFAULT") || (Integer) query.getData()[0][1] >= 30) {
                        logger.info(LogUtil.getHeading() + ChatColor.WHITE + event.getConnection().getName() + ChatColor.GREEN + " passed VPN check. [Known]");
                        return;
                    }
                }

                boolean isVPN;

                if (config.getNode("kick", "algorithm", "method").getString("cascade").equalsIgnoreCase("consensus")) {
                    double consensus = clamp(0.0d, 1.0d, config.getNode("kick", "algorithm", "min-consensus").getDouble(0.6d));
                    isVPN = api.consensus(ip) >= consensus;
                } else {
                    isVPN = api.cascade(ip);
                }

                if (isVPN) {
                    logger.info(LogUtil.getHeading() + ChatColor.WHITE + event.getConnection().getName() + ChatColor.DARK_RED + " found using a VPN. Kicking with defined message.");

                    event.setCancelled(true);
                    event.setCancelReason(config.getNode("kick", "message").getString(""));
                } else {
                    logger.info(LogUtil.getHeading() + ChatColor.WHITE + event.getConnection().getName() + ChatColor.GREEN + " passed VPN check.");
                }

            } catch (Throwable throwable) {
                logger.error(throwable.getMessage(), throwable);
            } finally {
                event.completeIntent(plugin);
            }
        });

    }

    private String getIp(InetSocketAddress address) {
        if (address == null) {
            return null;
        }

        InetAddress host = address.getAddress();
        if (host == null) {
            return null;
        }

        return host.getHostAddress();
    }

    private double clamp(double min, double max, double val) { return Math.min(max, Math.max(min, val)); }
}
