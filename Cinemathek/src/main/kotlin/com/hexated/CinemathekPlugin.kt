
package com.hexated

import com.lagradost.cloudstream3.plugins.CloudstreamPlugin
import com.lagradost.cloudstream3.plugins.Plugin
import android.content.Context

@CloudstreamPlugin
class CinemathekPlugin: Plugin() {
    override fun load(context: Context) {
        // All providers should be added in this manner. Please don't edit the providers list directly.
        registerMainAPI(Cinemathek())
        registerExtractorAPI(StreamwishCom())
        registerExtractorAPI(Ds2play())
        registerExtractorAPI(Do0od())
        registerExtractorAPI(Filelions())
        registerExtractorAPI(CinemathekOn())
    }
}