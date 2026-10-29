package com.oguzhanstech.hybridvpn.engine

import com.oguzhanstech.hybridvpn.engine.dns.DnsMessage
import com.oguzhanstech.hybridvpn.engine.dns.DnsMessageWriter
import com.oguzhanstech.hybridvpn.engine.dns.DnsQuestion
import com.oguzhanstech.hybridvpn.engine.dns.DnsRcode
import com.oguzhanstech.hybridvpn.engine.dns.DnsType
import com.oguzhanstech.hybridvpn.engine.dns.RData
import com.oguzhanstech.hybridvpn.engine.dns.UdpUpstream
import com.oguzhanstech.hybridvpn.engine.dns.UpstreamException
import com.oguzhanstech.hybridvpn.engine.dns.UpstreamSockets
import org.junit.Assert.assertEquals
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import kotlin.concurrent.thread

/** Exercises the real socket path against a loopback fake resolver. */
class UdpUpstreamTest {

    @Test fun ignoresSpoofedIdsAndRestoresClientId() {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { server ->
            val worker = thread {
                val buf = ByteArray(512)
                val packet = DatagramPacket(buf, buf.size)
                server.receive(packet)
                val q = DnsMessage.parse(buf, packet.length)
                // A forged answer with the wrong id arrives first and must be ignored.
                val forged = DnsMessageWriter.withId(
                    DnsMessageWriter.response(q, DnsRcode.NOERROR, listOf(q.questions[0] to RData.Address(byteArrayOf(6, 6, 6, 6)))),
                    (q.id + 1) and 0xFFFF,
                )
                server.send(DatagramPacket(forged, forged.size, packet.socketAddress))
                val real = DnsMessageWriter.response(q, DnsRcode.NOERROR, listOf(q.questions[0] to RData.Address(byteArrayOf(1, 1, 1, 1))))
                server.send(DatagramPacket(real, real.size, packet.socketAddress))
            }
            val upstream = UdpUpstream(listOf(InetSocketAddress(server.localAddress, server.localPort)), UpstreamSockets.Default)
            val response = DnsMessage.parse(upstream.exchange(DnsMessageWriter.query(0xBEEF, listOf(DnsQuestion("a.example", DnsType.A))), 2000))
            worker.join()
            assertEquals(0xBEEF, response.id)
            assertEquals(RData.Address(byteArrayOf(1, 1, 1, 1)), response.answers.single().data)
        }
    }

    @Test(expected = UpstreamException::class)
    fun timesOut() {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { silent ->
            UdpUpstream(listOf(InetSocketAddress(silent.localAddress, silent.localPort)), UpstreamSockets.Default)
                .exchange(DnsMessageWriter.query(1, listOf(DnsQuestion("a.example", DnsType.A))), 600)
        }
    }
}
