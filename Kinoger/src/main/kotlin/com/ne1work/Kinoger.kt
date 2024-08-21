package com.hexated
import android.util.Log
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.lagradost.cloudstream3.Episode
import com.lagradost.cloudstream3.HomePageResponse
import com.lagradost.cloudstream3.LoadResponse
import com.lagradost.cloudstream3.MainAPI
import com.lagradost.cloudstream3.MainPageRequest
import com.lagradost.cloudstream3.SearchResponse
import com.lagradost.cloudstream3.SubtitleFile
import com.lagradost.cloudstream3.TvType
import com.lagradost.cloudstream3.app
import com.lagradost.cloudstream3.fixUrlNull
import com.lagradost.cloudstream3.mainPageOf
import com.lagradost.cloudstream3.newHomePageResponse
import com.lagradost.cloudstream3.newTvSeriesLoadResponse
import com.lagradost.cloudstream3.newTvSeriesSearchResponse
import com.lagradost.cloudstream3.utils.ExtractorLink
import com.lagradost.cloudstream3.utils.getQualityFromName
import com.lagradost.cloudstream3.utils.loadExtractor
import com.lagradost.cloudstream3.utils.AppUtils
import com.lagradost.cloudstream3.utils.M3u8Helper
import com.lagradost.cloudstream3.utils.Qualities
import com.lagradost.cloudstream3.utils.getAndUnpack
import java.util.Base64
import org.jsoup.nodes.Element
import java.net.URI
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class Kinoger : MainAPI() {
    override var name = "Kinoger"
    override var mainUrl = "https://kinoger.to"
    override var lang = "de"
    override val hasMainPage = true
    override val supportedTypes = setOf(TvType.TvSeries, TvType.Movie)

    override val mainPage = mainPageOf(
        "" to "Alle Filme",
        "stream/action" to "Action",
        "stream/fantasy" to "Fantasy",
        "stream/drama" to "Drama",
        "stream/mystery" to "Mystery",
        "stream/romance" to "Romance",
        "stream/animation" to "Animation",
        "stream/horror" to "Horror",
        "stream/familie" to "Familie",
        "stream/komdie" to "Komdie",
    )

    val headers = mapOf("User-Agent" to "Mozilla/5.0 (Windows NT 10.0; rv:129.0) Gecko/20100101 Firefox/129.0",
        "Accept-Language" to "en-US,en;q=0.5",
        "Origin" to "https://kinoger.ru",
    )

    private suspend fun fetchVideoFileUrl(mirrorLink: String?): String? {
        if (mirrorLink.isNullOrBlank()) return ""
        val normalizedLink = normalizeLink(mirrorLink)
        return try {
            when {
                normalizedLink.contains("voe") -> fetchkingoVox(normalizedLink)
                else -> fetchGenericVideoUrl(normalizedLink)
            }
        } catch (e: Exception) {
            ""
        }
    }

    private fun normalizeLink(mirrorLink: String): String {
        return if (!mirrorLink.startsWith("https://")) {
            val linkWithoutScheme = mirrorLink.replace("//", "")
            "https://$linkWithoutScheme"
        } else {
            mirrorLink
        }
    }

    data class Voekingo (
        @SerializedName("file"                              ) var file                           : String?           = null,
    )

    private suspend fun  fetchkingoVox(url: String): String? {
        val regex = Regex("window.location.href = '([^']+)';")
        val doc = app.get(url , referer = mainUrl).text
        val matchResult = regex.find(doc)
        if (matchResult != null) {
            val redirect = matchResult.groupValues[1]
            println("Redirect: $redirect")
            val response = app.get(redirect, referer = url).text
            val regex2 = Regex("let\\s+\\w+\\s*=\\s*'([A-Za-z0-9+/=]+)';")
            val matchResult2 = regex2.find(response)
            if (matchResult2 != null) {
                val encryptedData = matchResult2.groupValues[1]
                val base64dec = Base64.getDecoder().decode(encryptedData).toString(Charsets.UTF_8)
                val json = Gson().fromJson(base64dec.reversed(), Voekingo::class.java)
                return json.file
            }
        }
        return null
    }


    suspend fun fetchGenericVideoUrl(url: String): String? {
        val doc = app.get(url , timeout = 5000 , referer = mainUrl).document

        val scripts = doc.select("script").map { it.html() }
        val pattern = Regex("""eval\(function\(p,a,c,k,e,d\).*?\)""")
        val videoScript = scripts.find { pattern.containsMatchIn(it) }
        if (videoScript != null) {
            val decompressedScript = getAndUnpack(videoScript)
            val imagePattern = Regex("""image\s*:\s*"([^"]+)"""")
            val imageUrl = imagePattern.find(decompressedScript)?.groupValues?.get(1)
            val baseUrl = imageUrl?.let { getBaseUrl(it) } ?: ""
            val regexTarget = """sources\s*:\s*\[\s*\{\s*file\s*:\s*"([^"]+)"""
            val regex = Regex(regexTarget)
            val matches = regex.findAll(decompressedScript)

            return matches.map { matchResult ->
                extractVideoUrl(baseUrl, matchResult)
            }.firstOrNull()
        }
        return null
    }

    private fun extractVideoUrl(baseUrl: String, matchResult: MatchResult): String {
        var videoUrl = matchResult.groupValues[1]
        if (videoUrl.startsWith("//")) {
            videoUrl = "https:" + videoUrl
        } else if (videoUrl.startsWith("/")) {
            videoUrl = baseUrl + videoUrl
        }
        if (!videoUrl.startsWith("https://")) {
            videoUrl = videoUrl.replace("http://", "https://")
        }

        return videoUrl
    }

    private fun getBaseUrl(imageUrl: String): String {
        val uri = URI(imageUrl)
        return "${uri.scheme}://${uri.host}"
    }

    override suspend fun getMainPage(page: Int, request: MainPageRequest): HomePageResponse {
        val document = app.get("$mainUrl/${request.data}/page/$page").document
        val home = document.select("div#dle-content div.short").mapNotNull {
            it.toSearchResult()
        }
        return newHomePageResponse(request.name, home)
    }

    private fun getProperLink(uri: String): String {
        return if (uri.contains("-episode-")) {
            "$mainUrl/series/" + Regex("$mainUrl/(.+)-ep.+").find(uri)?.groupValues?.get(1)
        } else {
            uri
        }
    }

    private fun Element.getImageAttr(): String? {
        return when {
            this.hasAttr("data-src") -> this.attr("data-src")
            this.hasAttr("data-lazy-src") -> this.attr("data-lazy-src")
            this.hasAttr("srcset") -> this.attr("srcset").substringBefore(" ")
            else -> this.attr("src")
        }
    }

    data class EncryptedData(
        val s: String,
        val iv: String,
        val ct: String
    )

    fun contentDecryptor(htmlContent: String, passphrase: String): String {

        val encryptedData = Gson().fromJson(htmlContent, EncryptedData::class.java)
        // Extract the salt, iv, and ciphertext from the JSON object
        val salt = hexStringToByteArray(encryptedData.s)
        val iv = hexStringToByteArray(encryptedData.iv)
        val ct = Base64.getDecoder().decode(encryptedData.ct)

        // Concatenate the passphrase and the salt
        val concatedPassphrase = passphrase.toByteArray(Charsets.UTF_8) + salt

        // Compute the MD5 hashes
        val md5List = mutableListOf<ByteArray>()
        md5List.add(md5(concatedPassphrase))
        var result = md5List[0]
        var i = 1
        while (result.size < 32) {
            md5List.add(md5(md5List[i - 1] + concatedPassphrase))
            result += md5List[i]
            i++
        }

        // Extract the key from the result
        val key = result.sliceArray(0 until 32)

        // Decrypt the ciphertext using AES-256-CBC
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val secretKey = SecretKeySpec(key, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
        val decrypted = cipher.doFinal(ct)

        return String(decrypted, Charsets.UTF_8)
    }

    private fun md5(input: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(input)
    }

    private fun hexStringToByteArray(hexString: String): ByteArray {
        val len = hexString.length
        val data = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            data[i / 2] = ((hexString[i].toString().toInt(16) shl 4) + hexString[i + 1].toString().toInt(16)).toByte()
        }
        return data
    }

    private fun Element.toSearchResult(): SearchResponse? {
        val href = getProperLink(this.selectFirst("a")?.attr("href") ?: return null)
        val title = this.selectFirst("a")?.text() ?: this.selectFirst("img")?.attr("alt")
        ?: this.selectFirst("a")?.attr("title") ?: return null
        val posterUrl = fixUrlNull(
            (this.selectFirst("div.content_text img") ?: this.nextElementSibling()?.selectFirst("div.content_text img") ?: this.selectFirst("img"))?.getImageAttr()
        )

        return newTvSeriesSearchResponse(title, href, TvType.AsianDrama) {
            this.posterUrl = posterUrl
        }
    }

    override suspend fun search(query: String): List<SearchResponse> {
        return app.get("$mainUrl/?do=search&subaction=search&titleonly=3&story=$query&x=0&y=0&submit=submit").document.select(
            "div#dle-content div.titlecontrol"
        ).mapNotNull { it.toSearchResult() }
    }

    override suspend fun load(url: String): LoadResponse {
        val document = app.get(url).document
        val title = document.selectFirst("h1#news-title")?.text() ?: ""
        val poster = fixUrlNull(document.selectFirst("div.images-border img")?.getImageAttr())
        val description = document.select("div.images-border").text()
        val year = """\((\d{4})\)""".toRegex().find(title)?.groupValues?.get(1)?.toIntOrNull()
        val tags = document.select("li.category a").map { it.text() }

        val recommendations = document.select("ul.ul_related li").mapNotNull {
            it.toSearchResult()
        }

        val keywordsRegex = Regex("kinoger\\.ru|(pw|fsst|go|ollhd)\\.show")

        val jsonData = document.select("script")
            .filter { script -> keywordsRegex.containsMatchIn(script.data() ?: "") }
            .mapNotNull { script ->
                val data = script.data()?.substringAfter("[")
                    ?.substringBeforeLast("]")
                    ?.replace("\'", "\"")
                AppUtils.tryParseJson<List<List<String>>>("[$data]")
            }
            .flatten()

        val lastScript = document.select("script:containsData(kinoger.ru)").lastOrNull()?.data()
        val type = if (lastScript?.substringBeforeLast(")")?.substringAfterLast(",") == "0.2") TvType.Movie else TvType.TvSeries

        val episodes = jsonData.flatMapIndexed { season: Int, iframes: List<String> ->
            iframes.mapIndexed { episode, iframe ->
                Episode(
                    data = if (type == TvType.Movie) jsonData.joinToString(",") else iframe,
                    season = season + 1,
                    episode = episode + 1
                )
            }
        } ?: emptyList()

        return newTvSeriesLoadResponse(title, url, type, episodes) {
            this.posterUrl = poster
            this.year = year
            this.plot = description
            this.tags = tags
            this.recommendations = recommendations
        }
    }



    override suspend fun loadLinks(
        data: String,
        isCasting: Boolean,
        subtitleCallback: (SubtitleFile) -> Unit,
        callback: (ExtractorLink) -> Unit
    ): Boolean {
        val regexContent = Regex("const Contents = '(.*)';")
        val regexSubtitles = Regex("tracks:\\s*\\[\\s*\\{(?:[^}]*\"file\"\\s*:\\s*\"([^\"]+)\"(?:[^}]*\"label\"\\s*:\\s*\"([^\"]*)\")?)?[^}]*\\}")
        val links = data.replace("[", "").replace("]", "")
            .split(",")
            .map { it.trim() }
        links.forEach { link ->
            if (link.contains("kinoger.ru")) {
                val doc = app.get(link, referer = mainUrl).text
                val matchContent = regexContent.find(doc)
                if (matchContent != null) {
                    val content = matchContent.groupValues[1]
                    val decryptedContent =
                        contentDecryptor(content, "1FHuaQhhcsKgpTRB").replace("\\", "")
                    val matchSubtitles = regexSubtitles.findAll(decryptedContent)
                    matchSubtitles.forEach { matchResult ->
                        val subtitleUrl = matchResult.groupValues[1]
                        val subtitleLabel = matchResult.groupValues[2]
                        subtitleCallback.invoke(
                            SubtitleFile(
                                subtitleLabel ?: "Unknown",
                                url = subtitleUrl
                            )
                        )
                    }
                }
                loadExtractor(link, link, subtitleCallback, callback)
            } else {
                val videoUrl = fetchVideoFileUrl(link)
                val name = when {
                    link.contains(".pw") -> "Lulustream"
                    link.contains(".re") -> "Filemoon"
                    link.contains("voe") -> "Voe"
                    else -> this.name
                }
                if (videoUrl != null) {
                    callback.invoke(
                        ExtractorLink(
                            source = name,
                            name,
                            videoUrl,
                            link,
                            quality = Qualities.Unknown.value,
                            isM3u8 = videoUrl.contains("m3u8")
                        )
                    )
                } else {
                    loadExtractor(link, link, subtitleCallback, callback)
                }
            }
        }
        return true
    }

}

