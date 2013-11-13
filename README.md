WSCoL-Tutorial-Twitter-REST
===========================

Show one of the possible use of [WSCoL](http://samguinea.github.io/wscol): retrieving data from the JSON obtained via Twitter's REST API v1.1.

## Table of Content
0. [Intro](#intro)
1. [Setup](#setup)
    1. [Download Libraries](#download-libraries)
    2. [Installation](#installation)
2. [Twitter Application Registration](#twitter-application-registration)
3. [Code](#code)
    - [Authentication Process](#authentication-process)
    - [Fetch Data](#fetch-data)
        + asd
        + asd
    - [Requests and Responses](#requests-and-responses)
    - [Whole Code](#whole-code)
4. [Project Structure](#project-structure)
5. [Conclusions](#conclusions)

# Intro
This tutorial is part of the example use cases of the [WSCoL](http://samguinea.github.io/wscol) language: an assertion constraint language extremely flexible.<br/>
Here we use it's capability for extract informations obtained via Twitter's REST APIs version 1.1, so from JSON response messages.<br/>
The example is based on an [application-only authentication](https://dev.twitter.com/docs/auth/application-only-auth) which doesn't need a program to login as a specific user. In this way, the set of accessible informations are the ones that are public (publicly accessible tweets, lists or user information), in a read-only manner (for example is useful for widgets and similar).<br/>
For this demo it's enough, but if interested in a deeper use of Twitter take a look at [     OAuth signed requests](https://dev.twitter.com/docs/auth/obtaining-access-tokens).

# Setup
The application is developed in Java: from the tests to the endpoints calls, that are made with a few methods.<br/>
If necessary there are specific Java library for Twitter (such as [Twitter4j](http://twitter4j.org)).

We're going to use [Eclipse IDE](http://eclipse.org/).

## Download Libraries

Required:

* WSCoL-Analyzer
* WSCoL
* [json-simple-1.1](https://code.google.com/p/json-simple/)
* [Apache Commonds Codec](http://commons.apache.org/proper/commons-codec/download_codec.cgi)

## Installation
Save libraries in a folder inside your project (we called it _lib_).<br/>
Then, from Eclipse, select the libraries, right click on them and select _Add to build path_ from the _Build path..._ voice.

![Add Libraries](https://github.com/rbrunetti/rbrunetti.github.io/blob/master/tutorial-images/twitter/00-ImportLibs.png)

# Twitter Application Registration
Now we need to register a new application, for granting the rights to use APIs. Note that a Twitter account is mandatory for proceed.<br/>

![Twitter Dev](https://github.com/rbrunetti/rbrunetti.github.io/blob/master/tutorial-images/twitter/01-DevTwitter.png)

Go to [https://dev.twitter.com](https://dev.twitter.com), sign up with your account and then select from the dropdown menu _My Application_.

![New Application](https://github.com/rbrunetti/rbrunetti.github.io/blob/master/tutorial-images/twitter/02-NewApp.png)

At this point, create a new application, filling all the required fields and go on.

![Application's Fields](https://github.com/rbrunetti/rbrunetti.github.io/blob/master/tutorial-images/twitter/03-AppInfo.png)

At the end of the day you'll have access to your application and its settings, in particular to the __Consumer Key__ and __Consumer Secret__ (remember that the latter must not be shared), that we'll use sooner.

![Application's Details](https://github.com/rbrunetti/rbrunetti.github.io/blob/master/tutorial-images/twitter/04-AppData.png)

# Code
In this section we illustrate the portions of code.

## Authentication Process
The procedure for Application-only authentication goes through the next steps:

1. Combine the key and secret together and encode it with a base64 encoding.
2. Use that new encoded key to ask Twitter for a _bearer token_.
3. Get the token back from Twitter, save it and then supply it in the headers of additional requests.

So, we have to create a function that will take consumer key and consumer secret, meld them together and encode them. For doing this we need to use the Apache Commonds Codec to encode the keys into base64.
```Java
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
```
Here we take in the key and secret, concatenate them together with a colon and then encode them using our Base64 object we got from the Apache Commons Codec package. Here we encoded them as UTF-8 encoding and return the encoded string.<br/>

At this point we can require a bearer token from Twitter using the encoding keys inside `encodedCredentials`. This will be supplied in the Authorization header and passed in a SSL connection to Twitter’s authentication URL. The token will be returned as a JSON object.
```Java
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
		// we use WSCoL Analyzer for extract data from something like "{"access_token":"AAAAAAAAAAAAAAAAAAAAAGXPUQAAAAA...","token_type":"bearer"}"
		String response = readResponse(connection);
		String assertion = "let $token = /access_token;\n $token.cardinality() != 0 && /token_type == \"bearer\";";
		Object token = null;
		if(evaluateWscol(response, assertion)) {
            // getVariable(str) returns the value corresponding to the passed variable name, the same as the one declared in WSCoL
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
```
Note that we've used WSCoL and WSCoL analyzer for handle the JSON and subsequently recall a WSCoL variable, using the `getVariable` method.

## Fetch Data

After getting the _bearer token_ we could supply it in the headers of additional requests, according to our rights (remember that we use application-only authentication, so not all the possible request are available).<br/>
Those choices are the following.

<a name="user_timeline"></a>
### GET statuses/user_timeline
&laquo;Returns a collection of the most recent Tweets posted by the user indicated by the <i>screen_name</i> or <i>user_id</i> parameters.&raquo;<br/>
In addition to <i>screen_name</i> there's another argument for the method referring to the number of Tweets to analyse, _count_.
Here's the method.
```Java
// Fetches the text of tweets from a given user's timeline
// see https://dev.twitter.com/docs/api/1.1/get/statuses/user_timeline
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
```
With the method `readResponse` we obtain the string containing the response to the previously request, sent through the connection and with the earned _bearer token_.<br/>
Then we write the WSCoL assertion we want to check: we get the text of all the tweets that has non-empty text and store them in `$tweets`, verifing that the response has at least one object (`/root.cardinality() > 0`).<br/>
Looking more closely at the assertions we can see that there is the step `/root`: this is introduced because the value reported by `response` is a JSON array, in this cases WSCoL assign that array to a generic key, precisely `root`, leading to the a default SDO (substantially a map admitting nesting).<br/>
If the evaluation of the WSCoL gives positive result, the value corresponding to variable `$tweets` will be assigned to `texts` (this call gives back an object of type Array).

<a name="search_tweets"></a>
### GET search/tweets
&laquo;Returns a collection of relevant Tweets matching a specified query.&raquo;.<br/>
With this request we're going to obtain some sort of tweets and return the <i>screen_name</i> of the authors of the tweet localized in Italy.

```Java
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
```
The flow is as in the previous case: get the response, fetch data with WSCoL and use them.<br/>
WSCoL selects the statuses where the language is italian (`/statuses[lang==\"it\"`), then, for each status, gets the <i>screen_name</i> of its user. The result is an array with the list of user's names.<br/>
The variable we extract is `$italian_user`.

<a name="trend_place"></a>
### GET trends/place
&laquo;Returns the top 10 trending topics for a specific WOEID, if trending information is available for it.&raquo;<br/>
(WOEID is the [Yahoo! Where On Earth ID](http://developer.yahoo.com/geo/geoplanet/) of the location to return trending information for).<br/>
In the next snippet we obtain the trending topics for a passed WOEID, the program is expecting the ones for Milan (see the WSCoL string).
```Java
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
```
The assertions checks the existence of at least an hashtag (`exists($elem in $trends, $elem.startsWith(\"#\"))`) and that the name of the city is 'Milan' (`/root/locations/name == \"Milan\"`).<br/>
As for the [user_timeline](#user_timeline), the response in a JSON array, so the `root` key will be generated.<br/>
This method returns `$trends` array.

<a name="rate_limit_status"></a>
### GET application/rate_limit_status
&laquo;Returns the current rate limits for methods belonging to the specified resource families.&raquo;<br/>
This GET method is related to the limitations of the use of APIs applied by Twitter (see [REST API Rate Limiting in v1.1](https://dev.twitter.com/docs/rate-limiting/1.1)).<br/>
Here we retrieve the state of our limits and calculate the percentage with respect to the thresholds.
```Java
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
		String assertion = "let $status_remain = /resources/statuses/statusesuser_timeline/remaining;" 
            + "let $status_limit = /resources/statuses/statusesuser_timeline/limit;" 
            + "let $status_available = $status_remain / $status_limit * 100;" 
            + "let $search_remain = /resources/search/searchtweets/remaining;" 
            + "let $search_limit = /resources/search/searchtweets/limit;" 
            + "let $search_available = $search_remain / $search_limit * 100;" 
            + "let $trends_place_remain = /resources/trends/trendsplace/remaining;" 
            + "let $trends_place_limit = /resources/trends/trendsplace/limit;" 
            + "let $trends_place_available = $trends_place_remain / $trends_place_limit * 100;" 
            + " !($status_available <= 0 || $search_available <= 0 || $trends_place_available <= 0);";

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
```
In this final case, we use the WSCoL for making simple arithmetic expression for calculating the percentage of use of each resourse, after getting the data from the JSON.<br/>
For details on resource family and requests limits see [here](https://dev.twitter.com/docs/rate-limiting/1.1/limits).<br/>
With the initial declaration limits, remaining requests and percertage are calculated; then the assertions checks that none of each limit has been excedeed (`!($status_available <= 0 || $search_available <= 0 || $trends_place_available <= 0)`).<br/>
There's another little thing: the JSON returned by Twitter has some keys with non-alphanumeric characters (for example the `/` in `/statuses/user_timeline`, also conflicting with the navigation steps), in this situation WSCoL strips away unallowed characters and replace them with a '-' in case of white space (`/statuses/user_timeline` as become `statusesuser_timeline`). Keep this in mind when making assertions.

## Requests and Responses
The last methods are helper functions for input and output streams:
```Java
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
```

## Whole Code
```Java
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

```

# Project Structure
The structure of the Java project

![Project Structure](https://github.com/rbrunetti/rbrunetti.github.io/blob/master/tutorial-images/twitter/05-ProjStruct.png)

# Conclusions
WSCoL is a powerful and flexible language, that could be used also for extracting data from JSON in a simpler and clearer way than usual.
