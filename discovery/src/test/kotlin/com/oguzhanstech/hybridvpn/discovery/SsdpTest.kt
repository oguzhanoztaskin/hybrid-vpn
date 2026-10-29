package com.oguzhanstech.hybridvpn.discovery

import com.oguzhanstech.hybridvpn.discovery.ssdp.SsdpDiscoverer
import com.oguzhanstech.hybridvpn.discovery.ssdp.SsdpParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SsdpTest {

    @Test fun parsesSearchResponse() {
        val headers = SsdpParser.parseHeaders(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n" +
                "SERVER: Linux UPnP/1.1 MiniUPnPd/2.2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
                "USN: uuid:ABCD-1234::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
        )!!
        assertEquals("http://192.168.1.1:5000/rootDesc.xml", headers["location"])
        assertEquals("abcd-1234", SsdpParser.uuidOf(headers["usn"]))
        assertNull(SsdpParser.parseHeaders("M-SEARCH * HTTP/1.1\r\n\r\n"))
    }

    @Test fun parsesDescriptionWithoutEvaluatingEntities() {
        val xml = """<?xml version="1.0"?>
            <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major></specVersion>
            <device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
            <friendlyName>Living Room &amp; Kitchen</friendlyName><manufacturer>&xxe;</manufacturer>
            <modelName>BRAVIA</modelName><UDN>uuid:4d696e69-444c-164e-9d41-001e2a58bd4e</UDN>
            <deviceList><device><friendlyName>Nested</friendlyName></device></deviceList></device></root>"""
        val d = SsdpParser.parseDescription(xml)
        assertEquals("Living Room & Kitchen", d.friendlyName)
        assertEquals("&xxe;", d.manufacturer)
        assertEquals("BRAVIA", d.modelName)
        assertEquals("4d696e69-444c-164e-9d41-001e2a58bd4e", SsdpParser.uuidOf(d.udn))
    }

    @Test fun readsPlainAndChunkedBodies() {
        val plain = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n<x>ä</x>".toByteArray()
        assertEquals("<x>ä</x>", SsdpDiscoverer.readHttpBody(plain.inputStream(), 1024))
        val body = "<x>ä</x>".toByteArray()
        val chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".toByteArray() +
            "${Integer.toHexString(body.size)}\r\n".toByteArray() + body + "\r\n0\r\n\r\n".toByteArray()
        assertEquals("<x>ä</x>", SsdpDiscoverer.readHttpBody(chunked.inputStream(), 1024))
        assertNull(SsdpDiscoverer.readHttpBody("HTTP/1.1 404 Not Found\r\n\r\n".toByteArray().inputStream(), 1024))
        assertNull(SsdpDiscoverer.readHttpBody(plain.inputStream(), 10))
    }
}
