package org.netmerge.android

import android.content.Context
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import java.io.Closeable
import java.io.IOException
import java.util.UUID
import kotlin.concurrent.thread

/**
 * Root owns ONLY the TUN adapter and policy rules.
 * The unprivileged Android app keeps the existing gomobile network engine.
 * No VpnService or VPN consent is used, so Tailscale can remain connected.
 */
internal class RootTunBridge {
    @Volatile private var server: LocalServerSocket? = null

    fun cancel() {
        runCatching { server?.close() }
        server = null
    }

    @Throws(IOException::class)
    fun open(context: Context): RootTunSession {
        val name = "nmroot." + Process.myPid() + "." + UUID.randomUUID().toString().replace("-", "")
        val listener = LocalServerSocket(name)
        server = listener
        try {
            val helper = context.applicationInfo.nativeLibraryDir + "/libnetmerge_root.so"
            val command = "exec '" + helper + "' '" + name + "'"
            val proc = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true).start()
            thread(name = "netmerge-root-log", isDaemon = true) {
                runCatching {
                    proc.inputStream.bufferedReader().forEachLine {
                        Log.i("NetMergeRoot", it)
                    }
                }
            }
            val socket = listener.accept()
            try {
                if (socket.peerCredentials.uid != 0) {
                    throw IOException("Root helper authentication failed")
                }
                if (socket.inputStream.read() != 'F'.code) {
                    throw IOException("Root helper did not send its TUN descriptor")
                }
                val fds = socket.ancillaryFileDescriptors
                if (fds == null || fds.isEmpty()) {
                    throw IOException("Root helper sent no file descriptor")
                }
                val dup = ParcelFileDescriptor.dup(fds[0])
                return RootTunSession(socket, dup)
            } catch (e: Exception) {
                socket.close()
                throw e
            }
        } finally {
            listener.close()
            if (server === listener) server = null
        }
    }
}

/**
 * The helper installs routes ONLY after activate(), when Go is ready for packets.
 * If the app crashes, the Unix socket closes and the helper removes those rules.
 */
internal class RootTunSession(
    private val socket: LocalSocket,
    private val fd: ParcelFileDescriptor,
) : Closeable {
    fun takeTunFd(): Int = fd.detachFd()

    @Throws(IOException::class)
    fun activate() {
        socket.outputStream.write('A'.code)
        socket.outputStream.flush()
        when (socket.inputStream.read()) {
            'R'.code -> Unit
            'E'.code -> throw IOException("Root helper failed to install policy routing")
            else -> throw IOException("Root helper exited before routing was activated")
        }
    }

    override fun close() {
        runCatching { socket.outputStream.write('S'.code) }
        runCatching { socket.close() }
        runCatching { fd.close() }
    }
}

