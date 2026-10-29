package com.oguzhanstech.hybridvpn.discovery.identity

data class Classification(val type: DeviceType, val vendor: String?, val model: String?, val suggestedName: String)

/** Heuristic, explainable classification from advertised services. Never authoritative. */
object DeviceClassifier {

    fun classify(o: HostObservation): Classification {
        val types = o.mdnsServices.map { it.type }.toSet()
        val txt = o.mdnsServices.fold(emptyMap<String, String>()) { acc, s -> s.txt + acc }
        val desc = o.ssdp?.description
        val targets = o.ssdp?.searchTargets.orEmpty().joinToString(" ").lowercase()
        val deviceInfoModel = o.mdnsServices.firstOrNull { it.type == "_device-info._tcp" }?.txt?.get("model")
        val model = desc?.modelName ?: txt["md"] ?: deviceInfoModel ?: txt["model"] ?: txt["ty"]
        val modelLower = (model ?: "").lowercase()
        val vendor = desc?.manufacturer ?: txt["manufacturer"] ?: txt["mfg"] ?: txt["usb_mfg"]
            ?: if (APPLE_MODEL.containsMatchIn(model ?: "") || "_companion-link._tcp" in types) "Apple" else null

        fun any(vararg t: String) = t.any { it in types }
        val type = when {
            o.isSelf -> DeviceType.PHONE
            o.isGateway || "internetgatewaydevice" in targets -> DeviceType.ROUTER
            any("_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp", "_uscan._tcp") ||
                9100 in o.openPorts -> DeviceType.PRINTER
            modelLower.contains("iphone") || modelLower.contains("ipad") || 62078 in o.openPorts -> DeviceType.PHONE
            any("_googlecast._tcp", "_amzn-wplay._tcp") || modelLower.contains("appletv") ||
                "dial-multiscreen" in targets || (desc?.friendlyName ?: "").contains("TV", ignoreCase = false) -> DeviceType.TV
            any("_raop._tcp", "_spotify-connect._tcp") || "zoneplayer" in targets -> DeviceType.SPEAKER
            any("_hap._tcp", "_matter._tcp", "_matterc._udp", "_hue._tcp", "_home-assistant._tcp") -> DeviceType.SMART_HOME
            any("_adisk._tcp") || (vendor ?: "").contains("synology", ignoreCase = true) || modelLower.contains("nas") -> DeviceType.NAS
            "mediaserver" in targets && !any("_workstation._tcp") -> DeviceType.NAS
            (554 in o.openPorts && o.openPorts.size <= 2) || modelLower.contains("camera") -> DeviceType.CAMERA
            modelLower.contains("playstation") || modelLower.contains("xbox") || modelLower.contains("nintendo") -> DeviceType.GAME_CONSOLE
            any("_workstation._tcp", "_ssh._tcp", "_sftp-ssh._tcp", "_rfb._tcp", "_smb._tcp", "_afpovertcp._tcp") ||
                APPLE_COMPUTER.containsMatchIn(model ?: "") || 22 in o.openPorts || 445 in o.openPorts -> DeviceType.COMPUTER
            else -> DeviceType.UNKNOWN
        }
        return Classification(type, vendor, model, suggestName(o, type, txt))
    }

    private fun suggestName(o: HostObservation, type: DeviceType, txt: Map<String, String>): String {
        o.ssdp?.description?.friendlyName?.let { return it }
        txt["fn"]?.takeIf { it.isNotBlank() }?.let { return it }
        val preferred = listOf("_device-info._tcp", "_airplay._tcp", "_workstation._tcp", "_raop._tcp", "_smb._tcp", "_ipp._tcp")
        for (t in preferred) {
            val instance = o.mdnsServices.firstOrNull { it.type == t }?.instance ?: continue
            // _raop instances are "<MAC>@<name>"; _workstation instances are "<name> [<MAC>]".
            return instance.substringAfter('@').substringBefore(" [").trim().ifEmpty { continue }
        }
        o.mdnsServices.firstOrNull()?.instance?.let { return it }
        o.mdnsHostname?.let { return it.removeSuffix(".local") }
        o.reverseDnsName?.let { return it.substringBefore('.') }
        val label = if (type == DeviceType.UNKNOWN) "Device" else type.name.lowercase().replace('_', ' ').replaceFirstChar { it.uppercase() }
        return "$label ${o.ip}"
    }

    private val APPLE_MODEL = Regex("^(iPhone|iPad|iPod|MacBook|Macmini|iMac|MacPro|Mac\\d|AppleTV|AudioAccessory|Watch)")
    private val APPLE_COMPUTER = Regex("^(MacBook|Macmini|iMac|MacPro|Mac\\d)")
}
