package com.oguzhanstech.hybridvpn.engine.dns

import java.net.IDN

enum class DomainScope {
    /** Only the exact name. Hosts-file and plain-domain semantics. */
    EXACT,
    /** The name and every subdomain. Adblock `||domain^` semantics. */
    SUBDOMAINS,
}

data class DomainRule(val domain: String, val scope: DomainScope, val exception: Boolean)

data class ParsedFilterList(
    val rules: List<DomainRule>,
    /** Syntactically recognised rules we deliberately do not implement (cosmetic, modifiers, regex, rewrites). */
    val unsupported: Int,
    val invalid: Int,
)

/**
 * Parses the DNS-relevant subset of AdGuard/Adblock syntax plus hosts files and plain domain lists.
 *
 * Unsupported rules are skipped and counted rather than approximated: silently widening a
 * modifier-restricted rule into a plain block would over-block, and approximating an exception
 * would under-block. Both are worse than a visible "N rules unsupported" count.
 */
object FilterListParser {

    private val NULL_ROUTES = setOf("0.0.0.0", "127.0.0.1", "::", "::0", "::1", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1")
    private val HOSTS_IGNORED = setOf(
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
        "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
    )
    private val ACCEPTED_MODIFIERS = setOf("important")
    private val WHITESPACE = Regex("\\s+")

    fun parse(text: String): ParsedFilterList {
        val rules = ArrayList<DomainRule>()
        var unsupported = 0
        var invalid = 0
        text.lineSequence().forEach { line ->
            when (val r = parseLine(line)) {
                is LineResult.Rules -> rules += r.rules
                LineResult.Unsupported -> unsupported++
                LineResult.Invalid -> invalid++
                LineResult.Ignored -> Unit
            }
        }
        return ParsedFilterList(rules, unsupported, invalid)
    }

    sealed interface LineResult {
        data class Rules(val rules: List<DomainRule>) : LineResult
        object Ignored : LineResult
        object Unsupported : LineResult
        object Invalid : LineResult
    }

    fun parseLine(raw: String): LineResult {
        val line = raw.trim()
        // '#' lines are hosts-file comments; generic cosmetic rules ("##.banner") are irrelevant to DNS anyway.
        if (line.isEmpty() || line.startsWith("!") || line.startsWith("[") || line.startsWith("#")) return LineResult.Ignored
        if (COSMETIC_MARKERS.any { line.contains(it) }) return LineResult.Unsupported

        var body = line
        val exception = body.startsWith("@@")
        if (exception) body = body.substring(2)

        if (body.startsWith("/") && body.endsWith("/") && body.length > 1) return LineResult.Unsupported

        if (body.startsWith("||") || body.startsWith("|")) {
            body = body.removePrefix("||").removePrefix("|")
            val scope = if (line.removePrefix("@@").startsWith("||")) DomainScope.SUBDOMAINS else DomainScope.EXACT
            val dollar = body.indexOf('$')
            if (dollar >= 0) {
                val modifiers = body.substring(dollar + 1).split(',').map { it.trim() }
                if (!modifiers.all { it in ACCEPTED_MODIFIERS }) return LineResult.Unsupported
                body = body.substring(0, dollar)
            }
            body = body.removeSuffix("|").removeSuffix("^")
            if (body.any { it == '*' || it == '/' || it == '^' || it == '|' || it == ':' }) return LineResult.Unsupported
            val domain = normalizeDomain(body) ?: return LineResult.Invalid
            return LineResult.Rules(listOf(DomainRule(domain, scope, exception)))
        }
        if (exception) return LineResult.Unsupported

        val withoutComment = body.substringBefore('#').trim()
        val tokens = withoutComment.split(WHITESPACE)
        if (tokens.size >= 2) {
            // hosts-file format: "<ip> <name> [<name>...]"
            if (tokens[0] !in NULL_ROUTES) return LineResult.Unsupported // a rewrite, not a block
            val rules = tokens.drop(1)
                .filter { it.lowercase() !in HOSTS_IGNORED }
                .mapNotNull { normalizeDomain(it) }
                .map { DomainRule(it, DomainScope.EXACT, exception = false) }
            return if (rules.isEmpty()) LineResult.Ignored else LineResult.Rules(rules)
        }

        if (withoutComment.any { it == '*' || it == '/' || it == '$' || it == '^' }) return LineResult.Unsupported
        val domain = normalizeDomain(withoutComment) ?: return LineResult.Invalid
        return LineResult.Rules(listOf(DomainRule(domain, DomainScope.EXACT, exception = false)))
    }

    private val COSMETIC_MARKERS = listOf("##", "#@#", "#?#", "#$#", "#%#", "\$\$")

    /** Lower-cased ASCII (punycode) form without a trailing dot, or null if not a hostname. */
    fun normalizeDomain(input: String): String? {
        val trimmed = input.trim().trimEnd('.').lowercase()
        if (trimmed.isEmpty() || trimmed.length > 253) return null
        val ascii = try {
            if (trimmed.all { it.code < 128 }) trimmed else IDN.toASCII(trimmed, IDN.ALLOW_UNASSIGNED).lowercase()
        } catch (_: IllegalArgumentException) {
            return null
        }
        val labels = ascii.split('.')
        if (labels.any { it.isEmpty() || it.length > 63 }) return null
        if (!labels.all { label -> label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' } }) return null
        return ascii
    }
}

/** Exact and suffix domain membership with O(labels) lookup. */
class DomainSet {
    private val exact = HashSet<String>()
    private val suffix = HashSet<String>()

    val size: Int get() = exact.size + suffix.size

    fun add(domain: String, scope: DomainScope) {
        if (scope == DomainScope.EXACT) exact += domain else suffix += domain
    }

    /** Returns the matching rule text (for logging), or null. [name] must already be normalised. */
    fun match(name: String): String? {
        if (name in exact) return name
        var candidate = name
        while (true) {
            if (candidate in suffix) return "||$candidate^"
            val dot = candidate.indexOf('.')
            if (dot < 0) return null
            candidate = candidate.substring(dot + 1)
        }
    }
}
