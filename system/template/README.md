# HTTP Messages

From this menu you may customize various HTTP error messages sent to users on HTTP frontend.

Whenever an error occurs in a Web application protected by Vulture, you can catch it and perform a custom action.
Supported actions are:
* Render HTML: Vulture will display the custom HTML code defined here
* Redirect with 302: Vulture will send a "302-REDIRECT" response to the user and redirect it to the URL defined here
* Redirect with 303: Vulture will send a "303-See Other" response to the user and redirect it to the URL defined here

You may ovveride the following event (please contact us if you need more !):
* 400 (Bad Request)
* 403 (Forbidden)
* 405 (Method Not Allowed)
* 408 (Request Timeout)
* 425 (Too Early)
* 429 (Too Many Requests)
* 500 (Internal Server Error)
* 502 (Bad Gateway)
* 503 (Service Unavailable)
* 504 (Gateway Timeout)
