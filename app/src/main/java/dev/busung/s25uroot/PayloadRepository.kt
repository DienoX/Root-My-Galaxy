package dev.busung.s25uroot

import android.content.Context
import android.system.Os
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
)

class PayloadRepository(private val context: Context) {

    fun loadTargets(): List<TargetProfile> {
        val manifestBytes = downloadBytes(
            "$RAW_REPOSITORY/main/support/targets-v3.json",
            MAX_MANIFEST_BYTES,
        )

        return SupportManifest.parse(manifestBytes).targets
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile =
        loadTargets()
            .firstOrNull { it.matches(snapshot) }
            ?: error(
                context.getString(
                    R.string.repo_no_profile,
                ),
            )

    fun resolveTarget(profileId: String): TargetProfile =
        loadTargets()
            .firstOrNull { it.profileId == profileId }
            ?: error(
                context.getString(
                    R.string.repo_profile_missing,
                    profileId,
                ),
            )

    fun download(
        profile: TargetProfile,
        onProgress: (String) -> Unit,
    ): VerifiedPayloads {

        val directory = File(
            context.filesDir,
            "payloads/${profile.profileId}",
        ).apply {
            mkdirs()
        }

        val exploit = downloadArtifact(
            profile.exploit,
            File(
                directory,
                "cve-2026-43499-app.so",
            ),
            context.getString(
                R.string.artifact_exploit,
            ),
            onProgress,
        )

        val kernelSu = downloadArtifact(
            profile.kernelSu,
            File(
                directory,
                "ksud-s25u-kdp",
            ),
            context.getString(
                R.string.artifact_kernelsu,
            ),
            onProgress,
        )

        Os.chmod(
            exploit.absolutePath,
            0b100100100,
        )

        Os.chmod(
            kernelSu.absolutePath,
            0b100100100,
        )

        return VerifiedPayloads(
            profile = profile,
            exploit = exploit,
            kernelSu = kernelSu,
        )
    }

    private fun downloadArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {

        onProgress(
            context.getString(
                R.string.repo_downloading,
                label,
            ),
        )

        val temporary = File(
            destination.parentFile,
            "${destination.name}.part",
        )

        if (temporary.exists()) {
            temporary.delete()
        }

        val connection = open(artifact.url)

        try {
            require(
                connection.contentLengthLong == -1L ||
                    connection.contentLengthLong == artifact.size,
            ) {
                context.getString(
                    R.string.repo_size_mismatch,
                    label,
                )
            }

            var total = 0L

            connection.inputStream.use { input ->
                FileOutputStream(temporary).use { output ->

                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)

                    while (true) {
                        val count = input.read(buffer)

                        if (count < 0) {
                            break
                        }

                        total += count

                        require(total <= artifact.size) {
                            context.getString(
                                R.string.repo_size_exceeded,
                                label,
                            )
                        }

                        output.write(
                            buffer,
                            0,
                            count,
                        )
                    }

                    output.fd.sync()
                }
            }

            require(total == artifact.size) {
                context.getString(
                    R.string.repo_incomplete,
                    label,
                )
            }
        } finally {
            connection.disconnect()
        }

        if (destination.exists()) {
            require(destination.delete()) {
                context.getString(
                    R.string.repo_finalize_failed,
                    label,
                )
            }
        }

        require(temporary.renameTo(destination)) {
            context.getString(
                R.string.repo_finalize_failed,
                label,
            )
        }

        onProgress(
            context.getString(
                R.string.repo_verified,
                label,
            ),
        )

        return destination
    }

    private fun downloadBytes(
        url: String,
        maximum: Int,
    ): ByteArray {

        val connection = open(url)

        return try {
            connection.inputStream.use { input ->

                val output = ByteArrayOutputStream()
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)

                while (true) {
                    val count = input.read(buffer)

                    if (count < 0) {
                        break
                    }

                    require(
                        output.size() + count <= maximum,
                    ) {
                        context.getString(
                            R.string.repo_response_too_large,
                        )
                    }

                    output.write(
                        buffer,
                        0,
                        count,
                    )
                }

                output.toByteArray()
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun open(
        url: String,
    ): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {

            connectTimeout = 15_000
            readTimeout = 60_000
            instanceFollowRedirects = true

            setRequestProperty(
                "User-Agent",
                "S25URoot/${BuildConfig.VERSION_NAME}",
            )

            connect()

            require(
                responseCode == HttpURLConnection.HTTP_OK,
            ) {
                "HTTP $responseCode"
            }
        }

    companion object {

        private const val RAW_REPOSITORY =
            "https://raw.githubusercontent.com/DienoX/Root-My-Galaxy-Payloads"

        private const val MAX_MANIFEST_BYTES =
            256 * 1024
    }
}
