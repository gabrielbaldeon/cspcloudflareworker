//Static nonce to be replaced
const staticNonce = "MjI5ODM2NDA1NCw0MjYzMzQxODkz"

//Content Security Policy object
const cspConfig = {
	"default-src": [
		"'none'",
	],
	"script-src": [
		"{{cspNonce}}",
		"'strict-dynamic'",
		"'unsafe-inline'",
		"'unsafe-eval'",		
		"https:",
	],
	"style-src": [
		"'self'",
		"'unsafe-inline'",
		"https://*.taggbox.com",
		"https://*.tagbox.com",
	],
	"object-src": [
		"'none'",
	],
	"base-uri": [
		"'none'",
	],
	"connect-src": [
		"'self'",
		"https://www.google-analytics.com",
		"https://www.google.com",
		"https://www.googleapis.com",
	],
	"font-src": [
		"'self'",
		"https://fonts.gstatic.com",
		"https://ka-f.fontawesome.com",
	],	
	"frame-src": [
		"'self'",
		"https://www.facebook.com",
		"https://www.google.com",		
	],
	"img-src": [
		"'self'",
		"https://umg-gtm-monitor-2lilwpfr.uc.gateway.dev",
		"https://www.facebook.com",
		"https://*.google.com",
		"data:",		
	],
	"manifest-src": [
		"'self'",
	],
	"media-src": [
		"'self'",
	],
};

//Generate the CSP Header
function generateCspHeaders(cspConfig, cspNonce) {
	return {
		"Content-Security-Policy": generateCspString(cspConfig, cspNonce)
	};
}

//Use a random cspNonce and insert it into the CSP object
function generateCspString(cspConfig, cspNonce) {
	let cspSections = [];

	Object.keys(cspConfig).map(function (key, index) {
		let values = cspConfig[key].map(function (value) {
			if (value === "{{cspNonce}}") {
				return value = `'nonce-${cspNonce}'`;
			}
			return value;
		})

		let cspSection = `${key} ${values.join(" ")}`;
		cspSections.push(cspSection);
	});

	return cspSections.join("; ");
}

let sanitiseHeaders = {
	"Server": "Worker",
};

let removeHeaders = [
	"Public-Key-Pins",
	"X-Powered-By",
	"X-AspNet-Version",
];

//Replaces the static nonce with the random new one
class AttributeRewriter {
	constructor(attributeName, oldValue, newValue) {
		this.attributeName = attributeName
		this.oldValue = oldValue;
		this.newValue = newValue;
	}
	element(element) {
		const attribute = element.getAttribute(this.attributeName)
		if (!(attribute === undefined || attribute === null)) {
            console.log("AutoNoncing");
			if (this.oldValue) {
				element.setAttribute(
					this.attributeName,
					attribute.replace(this.oldValue, this.newValue));
			}
		}
	}
}

//Intercept the Page request to replace the nonce and  inject the CSP
addEventListener('fetch', event => {
	return event.respondWith(addHeaders(event.request));
});

//Add the CSP to the page header
async function addHeaders(req) {
	let response = await fetch(req)
	let headers = new Headers(response.headers)

	if (headers.has("Content-Type") && !headers.get("Content-Type").includes("text/html")) {
		return new Response(response.body, {
			status: response.status,
			statusText: response.statusText,
			headers: headers
		});
	}

	// @ts-ignore
	let cspNonce = btoa(crypto.getRandomValues(new Uint32Array(2)));
	let cspHeaders = generateCspHeaders(cspConfig, cspNonce);

	Object.keys(cspHeaders).map(function (name, index) {
		headers.set(name, cspHeaders[name]);
	});

	Object.keys(sanitiseHeaders).map(function (name, index) {
		headers.set(name, sanitiseHeaders[name]);
	});

	removeHeaders.forEach(function (name) {
		headers.delete(name);
	});

	// Routing handler
	let status = response.status;
	let statusText = response.statusText;

	if (headers.has("Content-Type") &&
		headers.get("Content-Type").includes("text/html") &&
		status === 404) {
		status = 200;
		statusText = "OK";
	}

	// Auto-Nonce creation
	const rewriter = new HTMLRewriter()
		.on("script", new AttributeRewriter("nonce", staticNonce, cspNonce));

	return rewriter.transform(
		new Response(response.body, {
			status: status,
			statusText: statusText,
			headers: headers
		})
	);
}
