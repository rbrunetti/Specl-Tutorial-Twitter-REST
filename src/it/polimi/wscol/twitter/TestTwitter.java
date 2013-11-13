package it.polimi.wscol.twitter;

import it.polimi.wscol.WSCoLAnalyzer;
import it.polimi.wscol.dataobject.DataObject;
import it.polimi.wscol.helpers.WSCoLException;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.codec.binary.Base64;

public class TestTwitter {

	private static final String consumerKey = "<your consumerKey>";
	private static final String consumerSecret = "<your consumerSecret>";
	private static String bearerToken;
	private static WSCoLAnalyzer analyzer;

	@SuppressWarnings("unchecked")
	public static void main(String[] args) {
		
		System.out.println("### Getting Bearer Token: ");
		try {
			bearerToken = requestBearerToken("https://api.twitter.com/oauth2/token");
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		try {
			
			System.out.println("\n### TimeLineTweet:");
			ArrayList<Object> texts = (ArrayList<Object>) fetchTimelineTweet("twitterapi", 5);
			for (Object o : texts) {
				System.out.println("* " + o);
			}

			System.out.println("\n### SearchedTweet (in italian):");
			ArrayList<Object> names = (ArrayList<Object>) fetchSearchedTweet("europa", 100);
			for (Object o : names) {
				System.out.println("* " + o);
			}

			System.out.println("\n### Trends (related to WOEID):");
			ArrayList<Object> trends = (ArrayList<Object>) fetchTrendsByWOEID("718345");
			for (Object o : trends) {
				System.out.println("* " + o);
			}

			System.out.println("\n### Twitter Limits Status (available percetages):");
			Map<String, Object> avail = (Map<String, Object>) fetchRateLimitStatus();
			for (Entry<String, Object> o : avail.entrySet()) {
				System.out.println("* " + o.getKey() + " = " + o.getValue() + "%");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// Fetches the text of tweets from a given user's timeline
	private static Object fetchTimelineTweet(String screen_name, int count) throws IOException {
		HttpsURLConnection connection = null;

		String baseURL = "https://api.twitter.com/1.1/statuses/user_timeline.json";
		String endPointUrl = baseURL + "?screen_name=" + screen_name + "&count=" + count;
		
		try {
			URL url = new URL(endPointUrl);
			connection = (HttpsURLConnection) url.openConnection();
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.setRequestMethod("GET");
			connection.setRequestProperty("Host", "api.twitter.com");
			connection.setRequestProperty("User-Agent", "Your Program Name");
			connection.setRequestProperty("Authorization", "Bearer " + bearerToken);
			connection.setUseCaches(false);

			// Parse the JSON response into a JSON mapped object to fetch fields from.
//			String response = readResponse(connection);
//			evaluateWscol(response, "1==1;", null);
//			JSONArray obj = (JSONArray)JSONValue.parse(response);
//			if (obj != null) {
//				String tweet = ((JSONObject) obj.get(0)).get("text").toString();
//
//				return (tweet != null) ? tweet : "";
//			}
			
			String response = readResponse(connection);
			String assertion = "let $tweets = /root[text != \"\"]/text; /root.cardinality() > 0;";
			
			Object texts = null;
			if(evaluateWscol(response, assertion)) {
				texts = analyzer.getVariable("$tweets");
			}
			return (texts != null) ? texts : new String();
		} catch (MalformedURLException e) {
			throw new IOException("Invalid endpoint URL specified.", e);
		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}
	
	// Fetches the text of a collection of relevant Tweets matching a specified query, and return the screen-name of each italian related to the query
	// see https://dev.twitter.com/docs/api/1.1/get/search/tweets
	private static Object fetchSearchedTweet(String query, int count) throws IOException {
		HttpsURLConnection connection = null;

		String baseURL = "https://api.twitter.com/1.1/search/tweets.json";
		String endPointUrl = baseURL + "?q=" + URLEncoder.encode(query, "UTF-8") + "&count=" + count;

		try {
			URL url = new URL(endPointUrl);
			connection = (HttpsURLConnection) url.openConnection();
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.setRequestMethod("GET");
			connection.setRequestProperty("Host", "api.twitter.com");
			connection.setRequestProperty("User-Agent", "Your Program Name");
			connection.setRequestProperty("Authorization", "Bearer " + bearerToken);
			connection.setUseCaches(false);

			String response = readResponse(connection);
			String assertion = "let $italian_user = /statuses[lang==\"it\"]/user/screen_name; /statuses.cardinality() > 0;";

			Object itu = null;
			if(evaluateWscol(response, assertion)){
				itu = analyzer.getVariable("$italian_user");
			}
			return (itu != null) ? itu : new String();
		} catch (MalformedURLException e) {
			throw new IOException("Invalid endpoint URL specified.", e);
		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}
	
	// Fetches the top 10 trends from a given city's WOEID
	// see https://dev.twitter.com/docs/api/1.1/get/trends/place
	private static Object fetchTrendsByWOEID(String woeid) throws IOException {
		HttpsURLConnection connection = null;

		String baseURL = "https://api.twitter.com/1.1/trends/place.json";
		String endPointUrl = baseURL + "?id=" + woeid;

		try {
			URL url = new URL(endPointUrl);
			connection = (HttpsURLConnection) url.openConnection();
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.setRequestMethod("GET");
			connection.setRequestProperty("Host", "api.twitter.com");
			connection.setRequestProperty("User-Agent", "Your Program Name");
			connection.setRequestProperty("Authorization", "Bearer " + bearerToken);
			connection.setUseCaches(false);

			String response = readResponse(connection);
			String assertion = "let $trends = /root/trends/name;"
					+ "exists($elem in $trends, $elem.startsWith(\"#\")) && /root/locations/name == \"Milan\";";

			Object trends = null;
			if(evaluateWscol(response, assertion)) {
				trends = analyzer.getVariable("$trends");
			}
			return (trends != null) ? trends : new String();
		} catch (MalformedURLException e) {
			throw new IOException("Invalid endpoint URL specified.", e);
		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}
	
	// Fetches the status of the api limits
	// see https://dev.twitter.com/docs/api/1.1/get/application/rate_limit_status
	private static Map<String, Object> fetchRateLimitStatus() throws IOException {
		HttpsURLConnection connection = null;

		String endPointUrl = "https://api.twitter.com/1.1/application/rate_limit_status.json?resources=search,statuses,trends";

		try {
			URL url = new URL(endPointUrl);
			connection = (HttpsURLConnection) url.openConnection();
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.setRequestMethod("GET");
			connection.setRequestProperty("Host", "api.twitter.com");
			connection.setRequestProperty("User-Agent", "Your Program Name");
			connection.setRequestProperty("Authorization", "Bearer " + bearerToken);
			connection.setUseCaches(false);

			// Parse the JSON response into a JSON mapped object to fetch fields from.
			String response = readResponse(connection);
			String assertion = "" + "let $status_remain = /resources/statuses/statusesuser_timeline/remaining;" + "let $status_limit = /resources/statuses/statusesuser_timeline/limit;" + "let $status_available = $status_remain / $status_limit * 100;" + "let $search_remain = /resources/search/searchtweets/remaining;" + "let $search_limit = /resources/search/searchtweets/limit;" + "let $search_available = $search_remain / $search_limit * 100;" + "let $trends_place_remain = /resources/trends/trendsplace/remaining;" + "let $trends_place_limit = /resources/trends/trendsplace/limit;" + "let $trends_place_available = $trends_place_remain / $trends_place_limit * 100;" + " !($status_available <= 0 || $search_available <= 0 || $trends_place_available <= 0);";

			Object statusPercentage = null;
			Object searchPercentage = null;
			Object trendsPercentage = null;
			if (evaluateWscol(response, assertion)) {
				statusPercentage = analyzer.getVariable("$status_available");
				searchPercentage = analyzer.getVariable("$search_available");
				trendsPercentage = analyzer.getVariable("$trends_place_available");
			}
			if (statusPercentage != null && searchPercentage != null && trendsPercentage != null) {
				Map<String, Object> result = new HashMap<>();
				result.put("statusPercentage", statusPercentage);
				result.put("searchPercentage", searchPercentage);
				result.put("trendsPercentage", trendsPercentage);
				return result;
			}
			return null;
		} catch (MalformedURLException e) {
			throw new IOException("Invalid endpoint URL specified.", e);
		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	// Constructs the request for requesting a bearer token and returns that token as a string
	private static String requestBearerToken(String endPointUrl) throws IOException {
		HttpsURLConnection connection = null;
		String encodedCredentials = encodeKeys(consumerKey, consumerSecret);

		try {
			URL url = new URL(endPointUrl);
			connection = (HttpsURLConnection) url.openConnection();
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Host", "api.twitter.com");
			connection.setRequestProperty("User-Agent", "Your Program Name");
			connection.setRequestProperty("Authorization", "Basic " + encodedCredentials);
			connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8");
			connection.setRequestProperty("Content-Length", "29");
			connection.setUseCaches(false);

			writeRequest(connection, "grant_type=client_credentials");

			// Parse the JSON response into a JSON mapped object to fetch fields from.
			// JSONObject obj = (JSONObject)JSONValue.parse(readResponse(connection));
			// if (obj != null) {
			// String tokenType = (String)obj.get("token_type");
			// String token = (String)obj.get("access_token");
			//
			// return ((tokenType.equals("bearer")) && (token != null)) ? token : "";
			// }

			// something like "{"access_token":"AAAAAAAAAAAAAAAAAAAAAGXPUQAAAAA...","token_type":"bearer"}"
			String response = readResponse(connection);
			String assertion = "let $token = /access_token;\n $token.cardinality() != 0 && /token_type == \"bearer\";";
			Object token = null;
			if(evaluateWscol(response, assertion)) {
				token = analyzer.getVariable("$token");
			}
			return (token != null) ? (String) token : new String();
			
		} catch (MalformedURLException e) {
			throw new IOException("Invalid endpoint URL specified.", e);
		} finally {
			if (connection != null) {
				connection.disconnect();
			}
		}
	}

	// Encodes the consumer key and secret to create the basic authorization key
	private static String encodeKeys(String consumerKey, String consumerSecret) {
		try {
			String encodedConsumerKey = URLEncoder.encode(consumerKey, "UTF-8");
			String encodedConsumerSecret = URLEncoder.encode(consumerSecret, "UTF-8");

			String fullKey = encodedConsumerKey + ":" + encodedConsumerSecret;
			byte[] encodedBytes = Base64.encodeBase64(fullKey.getBytes());
			return new String(encodedBytes);
		} catch (UnsupportedEncodingException e) {
			return new String();
		}
	}

	// Writes a request to a connection
	private static boolean writeRequest(HttpsURLConnection connection, String textBody) {
		try {
			BufferedWriter wr = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));
			wr.write(textBody);
			wr.flush();
			wr.close();

			return true;
		} catch (IOException e) {
			return false;
		}
	}

	// Reads a response for a given connection and returns it as a string.
	private static String readResponse(HttpsURLConnection connection) {
		try {
			StringBuilder str = new StringBuilder();

			BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
			String line = "";
			while ((line = br.readLine()) != null) {
				str.append(line + System.getProperty("line.separator"));
			}
			return str.toString();
		} catch (IOException e) {
			return new String();
		}
	}

	private static boolean evaluateWscol(String jsonInput, String wscol) {
		analyzer = new WSCoLAnalyzer();
		analyzer.setJSONInput(jsonInput);
		DataObject a = WSCoLAnalyzer.getInput();
		a.getClass();
		try {
			return analyzer.evaluate(wscol);
		} catch (WSCoLException e) {
			// e.printStackTrace();
			return false;
		}
	}

}
