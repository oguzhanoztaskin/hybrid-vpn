package com.oguzhanstech.hybridvpn.engine.dns

/** A compiled filter list: what it blocks, and its own `@@` exceptions. */
class DomainList(val id: String, val blocked: DomainSet, val exceptions: DomainSet) {
    companion object {
        fun from(id: String, parsed: ParsedFilterList): DomainList {
            val blocked = DomainSet()
            val exceptions = DomainSet()
            for (rule in parsed.rules) {
                (if (rule.exception) exceptions else blocked).add(rule.domain, rule.scope)
            }
            return DomainList(id, blocked, exceptions)
        }
    }
}

data class DomainListMatch(val listId: String, val rule: String)

/**
 * All enabled domain lists. Exceptions (`@@`) from any list apply to every list, matching how
 * AdGuard combines filter lists; this is what lets a user allowlist override a third-party blocklist.
 */
class DomainListIndex(lists: Collection<DomainList>) {

    private val byId: Map<String, DomainList> = lists.associateBy { it.id }
    val ids: Set<String> get() = byId.keys

    fun exception(domain: String): DomainListMatch? {
        for (list in byId.values) {
            list.exceptions.match(domain)?.let { return DomainListMatch(list.id, "@@$it") }
        }
        return null
    }

    /** Whether [domain] is blocked by list [listId] (or by any list for [ANY_LIST]), honouring exceptions. */
    fun match(listId: String, domain: String): DomainListMatch? {
        if (exception(domain) != null) return null
        if (listId == ANY_LIST) {
            for (list in byId.values) list.blocked.match(domain)?.let { return DomainListMatch(list.id, it) }
            return null
        }
        val list = byId[listId] ?: return null
        return list.blocked.match(domain)?.let { DomainListMatch(list.id, it) }
    }

    companion object {
        /** Policy token matching every enabled list. */
        const val ANY_LIST = "@all"
        val EMPTY = DomainListIndex(emptyList())
    }
}
