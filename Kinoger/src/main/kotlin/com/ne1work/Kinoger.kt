package com.hexated

import com.google.gson.Gson
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
import java.util.Base64
import org.jsoup.nodes.Element
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class Kinogeru : Kinoger() {
    override val name = "Kinoger"
    override val mainUrl = "https://kinoger.ru"
}

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
            val salt = hexStringToByteArray(encryptedData.s)
            val iv = hexStringToByteArray(encryptedData.iv)
            val ct = Base64.getDecoder().decode(encryptedData.ct)
            val concatedPassphrase = passphrase.toByteArray(Charsets.UTF_8) + salt
            val md5List = mutableListOf<ByteArray>()
            md5List.add(md5(concatedPassphrase))
            var result = md5List[0]
            var i = 1
            while (result.size < 32) {
                md5List.add(md5(md5List[i - 1] + concatedPassphrase))
                result += md5List[i]
                i++
            }

            val key = result.sliceArray(0 until 32)
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

        val scripts = document.select("script").mapNotNull { script ->
            val scriptContent = script.data()
            val showPattern = Regex("""show\s*\(\s*\d+\s*,\s*\[\[(.*?)\]\],\s*0\.2""")
            val extractedData = showPattern.findAll(scriptContent)
                .map { it.groupValues[1].replace("'", "\"") }
                .joinToString(",")
            println("Extracted Data: $extractedData") // Print extracted data
            extractedData
        }

        val jsonData = scripts.flatMap { data ->
            val parsedData = AppUtils.tryParseJson<List<List<String>>>("[[$data]]")
            parsedData ?: emptyList()
        }.filter { it.isNotEmpty() }
        println("Jsondata "+jsonData)

        val type = if (document.select("script").any { it.data().contains("0.2") }) TvType.Movie else TvType.TvSeries

        val episodes = jsonData.flatMapIndexed { season: Int, iframes: List<String> ->
            iframes.mapIndexed { episode, iframe ->
                Episode(
                    jsonData.joinToString(","),
                    season = season + 1,
                    episode = episode + 1
                )
            }
        }

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
        val regexFileLink = Regex("sources:\\s*\\[\\s*\\{[^}]*\"file\"\\s*:\\s*\"([^\"]+)\"")
        val regexSubtitles = Regex("tracks:\\s*\\[\\s*\\{(?:[^}]*\"file\"\\s*:\\s*\"([^\"]+)\"(?:[^}]*\"label\"\\s*:\\s*\"([^\"]*)\")?)?[^}]*\\}")
        val links = data.replace("[", "").replace("]", "")
            .split(",")
            .map { it.trim() }
        links.forEach { link ->
            if (link.contains("kinoger")) {
                val doc = app.get(link, referer = mainUrl).text
                val matchContent = regexContent.find(doc)
                if (matchContent != null) {
                    val content = matchContent.groupValues[1]
                    val decryptedContent = contentDecryptor(content, "1FHuaQhhcsKgpTRB").replace("\\", "")


                    val matchFileLink = regexFileLink.findAll(decryptedContent)
                    matchFileLink.forEach { matchResult ->
                        val fileLink = matchResult.groupValues[1]
                        callback.invoke(
                            ExtractorLink(
                                "kinoger",
                                "kinoger",
                                fileLink,
                                link,
                                quality = getQualityFromName(name),
                                isM3u8 = fileLink.contains(".m3u8")
                            )
                        )
                    }

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
            } else {
                loadExtractor(link, mainUrl, subtitleCallback, callback)
            }

        }
        return true
    }

}
