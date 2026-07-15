package com.dpi.types;

import java.util.Locale;

/**
 * Application type classification.
 * Maps 1:1 with the C++ AppType enum in types.h.
 */
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;

    /**
     * Human-readable display name for each app type.
     */
    public String displayName() {
        switch (this) {
            case UNKNOWN:    return "Unknown";
            case HTTP:       return "HTTP";
            case HTTPS:      return "HTTPS";
            case DNS:        return "DNS";
            case TLS:        return "TLS";
            case QUIC:       return "QUIC";
            case GOOGLE:     return "Google";
            case FACEBOOK:   return "Facebook";
            case YOUTUBE:    return "YouTube";
            case TWITTER:    return "Twitter/X";
            case INSTAGRAM:  return "Instagram";
            case NETFLIX:    return "Netflix";
            case AMAZON:     return "Amazon";
            case MICROSOFT:  return "Microsoft";
            case APPLE:      return "Apple";
            case WHATSAPP:   return "WhatsApp";
            case TELEGRAM:   return "Telegram";
            case TIKTOK:     return "TikTok";
            case SPOTIFY:    return "Spotify";
            case ZOOM:       return "Zoom";
            case DISCORD:    return "Discord";
            case GITHUB:     return "GitHub";
            case CLOUDFLARE: return "Cloudflare";
            default:         return "Unknown";
        }
    }

    /**
     * Classify a domain/SNI string into an AppType.
     * Mirrors sniToAppType() from types.cpp.
     */
    public static AppType fromSNI(String sni) {
        if (sni == null || sni.isEmpty()) return UNKNOWN;

        String lower = sni.toLowerCase(Locale.ROOT);

        // YouTube (check before Google since ytimg contains neither "google" nor "youtube" in some CDN names)
        if (lower.contains("youtube") || lower.contains("ytimg") ||
                lower.contains("youtu.be") || lower.contains("yt3.ggpht")) {
            return YOUTUBE;
        }

        // Google
        if (lower.contains("google") || lower.contains("gstatic") ||
                lower.contains("googleapis") || lower.contains("ggpht") ||
                lower.contains("gvt1")) {
            return GOOGLE;
        }

        // Instagram (before Facebook — it's a Meta product with different domain)
        if (lower.contains("instagram") || lower.contains("cdninstagram")) {
            return INSTAGRAM;
        }

        // WhatsApp
        if (lower.contains("whatsapp") || lower.contains("wa.me")) {
            return WHATSAPP;
        }

        // Facebook/Meta
        if (lower.contains("facebook") || lower.contains("fbcdn") ||
                lower.contains("fb.com") || lower.contains("fbsbx") ||
                lower.contains("meta.com")) {
            return FACEBOOK;
        }

        // Twitter/X
        if (lower.contains("twitter") || lower.contains("twimg") ||
                lower.contains("x.com") || lower.contains("t.co")) {
            return TWITTER;
        }

        // Netflix
        if (lower.contains("netflix") || lower.contains("nflxvideo") ||
                lower.contains("nflximg")) {
            return NETFLIX;
        }

        // Amazon
        if (lower.contains("amazon") || lower.contains("amazonaws") ||
                lower.contains("cloudfront") || lower.contains("aws")) {
            return AMAZON;
        }

        // Microsoft
        if (lower.contains("microsoft") || lower.contains("msn.com") ||
                lower.contains("office") || lower.contains("azure") ||
                lower.contains("live.com") || lower.contains("outlook") ||
                lower.contains("bing")) {
            return MICROSOFT;
        }

        // Apple
        if (lower.contains("apple") || lower.contains("icloud") ||
                lower.contains("mzstatic") || lower.contains("itunes")) {
            return APPLE;
        }

        // Telegram
        if (lower.contains("telegram") || lower.contains("t.me")) {
            return TELEGRAM;
        }

        // TikTok
        if (lower.contains("tiktok") || lower.contains("tiktokcdn") ||
                lower.contains("musical.ly") || lower.contains("bytedance")) {
            return TIKTOK;
        }

        // Spotify
        if (lower.contains("spotify") || lower.contains("scdn.co")) {
            return SPOTIFY;
        }

        // Zoom
        if (lower.contains("zoom")) {
            return ZOOM;
        }

        // Discord
        if (lower.contains("discord") || lower.contains("discordapp")) {
            return DISCORD;
        }

        // GitHub
        if (lower.contains("github") || lower.contains("githubusercontent")) {
            return GITHUB;
        }

        // Cloudflare
        if (lower.contains("cloudflare") || lower.contains("cf-")) {
            return CLOUDFLARE;
        }

        // SNI present but unrecognized
        return HTTPS;
    }

    /**
     * Find AppType by its display name (for CLI parsing).
     */
    public static AppType fromDisplayName(String name) {
        for (AppType t : values()) {
            if (t.displayName().equalsIgnoreCase(name) || t.name().equalsIgnoreCase(name)) {
                return t;
            }
        }
        return null;
    }
}
