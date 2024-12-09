package com.github.topi314.lavasrc.deezer;

import com.github.topi314.lavasrc.ExtendedAudioTrack;
import com.github.topi314.lavasrc.LavaSrcTools;
import com.sedmelluq.discord.lavaplayer.container.flac.FlacAudioTrack;
import com.sedmelluq.discord.lavaplayer.container.mp3.Mp3AudioTrack;
import com.sedmelluq.discord.lavaplayer.container.mpeg.MpegAudioTrack;
import com.sedmelluq.discord.lavaplayer.source.AudioSourceManager;
import com.sedmelluq.discord.lavaplayer.tools.FriendlyException;
import com.sedmelluq.discord.lavaplayer.tools.JsonBrowser;
import com.sedmelluq.discord.lavaplayer.tools.Units;
import com.sedmelluq.discord.lavaplayer.tools.io.HttpInterface;
import com.sedmelluq.discord.lavaplayer.tools.io.PersistentHttpStream;
import com.sedmelluq.discord.lavaplayer.track.AudioTrack;
import com.sedmelluq.discord.lavaplayer.track.AudioTrackInfo;
import com.sedmelluq.discord.lavaplayer.track.InternalAudioTrack;
import com.sedmelluq.discord.lavaplayer.track.playback.LocalAudioTrackExecutor;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.client.CookieStore;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.BiFunction;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class DeezerAudioTrack extends ExtendedAudioTrack {

	private final DeezerAudioSourceManager sourceManager;
	private final CookieStore cookieStore;

	public DeezerAudioTrack(AudioTrackInfo trackInfo, DeezerAudioSourceManager sourceManager) {
		this(trackInfo, null, null, null, null, null, false, sourceManager);
	}

	public DeezerAudioTrack(AudioTrackInfo trackInfo, String albumName, String albumUrl, String artistUrl, String artistArtworkUrl, String previewUrl, boolean isPreview, DeezerAudioSourceManager sourceManager) {
		super(trackInfo, albumName, albumUrl, artistUrl, artistArtworkUrl, previewUrl, isPreview);
		this.sourceManager = sourceManager;
		this.cookieStore = new BasicCookieStore();
	}

	private static String formatFormats(TrackFormat[] formats) {
		var strFormats = new ArrayList<String>();
		for (var format : formats) {
			strFormats.add("{\"cipher\":\"BF_CBC_STRIPE\",\"format\":\"" + format.name() + "\"}");
		}
		return String.join(",", strFormats);
	}

	private JsonBrowser getJsonResponse(HttpUriRequest request, boolean useArl) throws IOException {
		try (HttpInterface httpInterface = this.sourceManager.getHttpInterface()) {
			httpInterface.getContext().setRequestConfig(RequestConfig.custom().setCookieSpec("standard").build());
			httpInterface.getContext().setCookieStore(cookieStore);

			if (useArl && this.sourceManager.getArl() != null) {
				request.setHeader("Cookie", "arl=" + this.sourceManager.getArl());
			}

			return LavaSrcTools.fetchResponseAsJson(httpInterface, request);
		}
	}

	private String getSessionId() throws IOException {
		var getSessionID = new HttpPost(DeezerAudioSourceManager.PRIVATE_API_BASE + "?method=deezer.ping&input=3&api_version=1.0&api_token=");
		var sessionIdJson = this.getJsonResponse(getSessionID, false);

		DeezerAudioSourceManager.checkResponse(sessionIdJson, "Failed to get session ID: ");
		return sessionIdJson.get("results").get("SESSION").text();
	}

	private LicenseToken generateLicenceToken(boolean useArl) throws IOException {
		var request = new HttpGet(DeezerAudioSourceManager.PRIVATE_API_BASE + "?method=deezer.getUserData&input=3&api_version=1.0&api_token=");

		// session ID is not needed with ARL and vice-versa.
		if (!useArl || this.sourceManager.getArl() == null) {
			request.setHeader("Cookie", "sid=" + this.getSessionId());
		}

		var json = this.getJsonResponse(request, useArl);
		DeezerAudioSourceManager.checkResponse(json, "Failed to get user token: ");

		return new LicenseToken(
			json.get("results").get("USER").get("OPTIONS").get("license_token").text(),
			json.get("results").get("checkForm").text()
		);
	}

	public SourceWithFormat getSource(boolean useArl, boolean isRetry) throws IOException, URISyntaxException {
		var licenseToken = this.generateLicenceToken(useArl);

		var getTrackToken = new HttpPost(DeezerAudioSourceManager.PRIVATE_API_BASE + "?method=song.getData&input=3&api_version=1.0&api_token=" + licenseToken.apiToken);
		getTrackToken.setEntity(new StringEntity("{\"sng_id\":\"" + this.trackInfo.identifier + "\"}", ContentType.APPLICATION_JSON));
		var trackTokenJson = this.getJsonResponse(getTrackToken, useArl);
		DeezerAudioSourceManager.checkResponse(trackTokenJson, "Failed to get track token: ");

		if (trackTokenJson.get("error").get("VALID_TOKEN_REQUIRED").text() != null && !isRetry) {
			// "error":{"VALID_TOKEN_REQUIRED":"Invalid CSRF token"}
			// seems to indicate an invalid API token?
			return this.getSource(useArl, true);
		}

		var trackToken = trackTokenJson.get("results").get("TRACK_TOKEN").text();

		var getMediaURL = new HttpPost(DeezerAudioSourceManager.MEDIA_BASE + "/get_url");
		getMediaURL.setEntity(new StringEntity("{\"license_token\":\"" + licenseToken.userLicenseToken + "\",\"media\":[{\"type\":\"FULL\",\"formats\":[" + formatFormats(this.sourceManager.getFormats()) + "]}],\"track_tokens\": [\"" + trackToken + "\"]}", ContentType.APPLICATION_JSON));

		var json = this.getJsonResponse(getMediaURL, useArl);
		for (var error : json.get("data").get("errors").values()) {
			if (error.get("code").asLong(0) == 2000) {
				// error code 2000 = failed to decode track token
				return this.getSource(useArl, true);
			}
		}
		DeezerAudioSourceManager.checkResponse(json, "Failed to get media URL: ");

		return SourceWithFormat.fromResponse(json, trackTokenJson);
	}

	public SourceWithFormat getMedia(boolean useArl) throws IOException, URISyntaxException {
		System.out.println("Using ARL: " + useArl);
		var licenseToken = this.generateLicenceToken(useArl);
       
		var getTrackToken = new HttpPost(DeezerAudioSourceManager.PRIVATE_API_BASE + "?method=song.getListData&input=3&api_version=1.0&api_token=" + licenseToken.apiToken);
		getTrackToken.setEntity(new StringEntity(String.format("{\"sng_ids\":[\"%s\"]}", this.trackInfo.identifier), ContentType.APPLICATION_JSON));
		var trackTokenJson = this.getJsonResponse(getTrackToken, useArl);
		DeezerAudioSourceManager.checkResponse(trackTokenJson, "Failed to get track token: ");

		var md5Origin ="3aad7cd250f4de7c4c9afa225a598b35"; //trackTokenJson.get("results").get("data").values().get(0).get("MD5_ORIGIN").text();
        var mediaVersion = "9";//trackTokenJson.get("results").get("data").values().get(0).get("MEDIA_VERSION").text();
		var url = generateTrackUrl(this.getIdentifier().toString() , md5Origin, mediaVersion.toString(), 1);
		return new SourceWithFormat(url  , TrackFormat.MP3_128, 3142634);

	}

	public static String bytesToHex(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

	public String generateTrackUrl(String trackId, String md5origin, String mediaVersion, int quality) {
        try {
            int magic = 164;

            ByteArrayOutputStream step1 = new ByteArrayOutputStream();
            step1.write(md5origin.getBytes());
            step1.write(magic);
            step1.write(Integer.toString(quality).getBytes());
            step1.write(magic);
            step1.write(trackId.getBytes());
            step1.write(magic);
            step1.write(mediaVersion.getBytes());
            //Get MD5
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(step1.toByteArray());
            byte[] digest = md5.digest();
            String md5hex = bytesToHex(digest).toLowerCase();

        
			
            ByteArrayOutputStream step2 = new ByteArrayOutputStream();
            step2.write(md5hex.getBytes());
            step2.write(magic);
            step2.write(step1.toByteArray());
            step2.write(magic);

          
            while(step2.size()%16 > 0) step2.write(46);

           
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec key = new SecretKeySpec("jo6aey6haid2Teih".getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
          
            StringBuilder step3 = new StringBuilder();
            for (int i=0; i<step2.size()/16; i++) {
                byte[] b = Arrays.copyOfRange(step2.toByteArray(), i*16, (i+1)*16);
                step3.append(bytesToHex(cipher.doFinal(b)).toLowerCase());
            }

            return "https://e-cdns-proxy-" + md5origin.charAt(0) + ".dzcdn.net/mobile/1/" + step3;

        } catch (Exception e) {
            e.printStackTrace();
           // log.error("Error generating track URL! ID: " + trackId + " " + e);
        }
        return null;
    }

	public byte[] getTrackDecryptionKey() throws NoSuchAlgorithmException {
		var md5 = Hex.encodeHex(MessageDigest.getInstance("MD5").digest(this.trackInfo.identifier.getBytes()), true);
		var master_key = this.sourceManager.getMasterDecryptionKey().getBytes();

		var key = new byte[16];
		for (int i = 0; i < 16; i++) {
			key[i] = (byte) (md5[i] ^ md5[i + 16] ^ master_key[i]);
		}
		return key;
	}

	@Override
	public void process(LocalAudioTrackExecutor executor) throws Exception {
		try (var httpInterface = this.sourceManager.getHttpInterface()) {
			if (this.isPreview) {
				if (this.previewUrl == null) {
					throw new FriendlyException("No preview url found", FriendlyException.Severity.COMMON, new IllegalArgumentException());
				}

				try (var stream = new PersistentHttpStream(httpInterface, new URI(this.previewUrl), this.trackInfo.length)) {
					processDelegate(new Mp3AudioTrack(this.trackInfo, stream), executor);
				}
				return;
			}

			//var source = this.getSource(this.sourceManager.getArl() != null, false);
			var source = this.getMedia(true);
			try (var stream = new DeezerPersistentHttpStream(httpInterface, source.url, source.contentLength, this.getTrackDecryptionKey())) {
				processDelegate(source.format.trackFactory.apply(this.trackInfo, stream), executor);
			}
		}
	}

	@Override
	protected AudioTrack makeShallowClone() {
		return new DeezerAudioTrack(this.trackInfo, this.albumName, this.albumUrl, this.artistUrl, this.artistArtworkUrl, this.previewUrl, this.isPreview, this.sourceManager);
	}

	@Override
	public AudioSourceManager getSourceManager() {
		return this.sourceManager;
	}

	public enum TrackFormat {
		FLAC(true, FlacAudioTrack::new),
		MP3_320(true, Mp3AudioTrack::new),
		MP3_256(true, Mp3AudioTrack::new),
		MP3_128(false, Mp3AudioTrack::new),
		MP3_64(false, Mp3AudioTrack::new),
		AAC_64(true, MpegAudioTrack::new); // not sure if this one is so better to be safe.

		private boolean isPremiumFormat;
		private BiFunction<AudioTrackInfo, PersistentHttpStream, InternalAudioTrack> trackFactory;

		public static final TrackFormat[] DEFAULT_FORMATS = new TrackFormat[]{MP3_128, MP3_64};

		TrackFormat(boolean isPremiumFormat, BiFunction<AudioTrackInfo, PersistentHttpStream, InternalAudioTrack> trackFactory) {
			this.isPremiumFormat = isPremiumFormat;
			this.trackFactory = trackFactory;
		}

		public static TrackFormat from(String format) {
			return Arrays.stream(TrackFormat.values())
				.filter(it -> it.name().equals(format))
				.findFirst()
				.orElse(null);
		}
	}

	private static class LicenseToken {
		private final String userLicenseToken;
		private final String apiToken;

		private LicenseToken(String userLicenseToken, String apiToken) {
			this.userLicenseToken = userLicenseToken;
			this.apiToken = apiToken;
		}
	}

	public static class SourceWithFormat {
		private final URI url;
		private final TrackFormat format;
		private final long contentLength;

		private SourceWithFormat(String url, TrackFormat format, long contentLength) throws URISyntaxException {
			this.url = new URI(url);
			this.format = format;
			this.contentLength = contentLength;
		}

		private static SourceWithFormat fromResponse(JsonBrowser json, JsonBrowser trackJson) throws URISyntaxException {
			var media = json.get("data").index(0).get("media").index(0);
			if (media.isNull()) {
				return null;
			}

			var format = media.get("format").text();
			var url = media.get("sources").index(0).get("url").text();
			var contentLength = trackJson.get("results").get("FILESIZE_" + format).asLong(Units.CONTENT_LENGTH_UNKNOWN);
			return new SourceWithFormat(url, TrackFormat.from(format), contentLength);
		}

		public URI getUrl() {
			return this.url;
		}

		public TrackFormat getFormat() {
			return this.format;
		}

		public long getContentLength() {
			return this.contentLength;
		}

	}
}
