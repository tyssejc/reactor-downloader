/*
Copyright 2019 Adobe. All rights reserved.
This file is licensed to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
OF ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations under the License.
*/

const fs = require("fs");
const { default: fetch } = require("node-fetch-cjs");

module.exports = async (settings) => {
	const integration = settings.integration;
	const environment = settings.environment;

	// check to make sure we have all of the correct information in the settings file
	if (!integration) {
		throw Error('settings file does not have an "integration" property.');
	}
	if (!integration.techAccountId) {
		throw Error('settings file does not have an "integration.techAccountId" property.');
	}
	if (!integration.orgId) {
		throw Error('settings file does not have an "integration.orgId" property.');
	}
	if (!integration.clientId) {
		throw Error('settings file does not have an "integration.clientId" property.');
	}
	if (!integration.clientSecret) {
		throw Error('settings file does not have an "integration.clientSecret" property.');
	}
	if (!integration.payload) {
		throw Error('settings file does not have an "integration.payload" property.');
	}
	if (!environment) {
		throw Error('settings file does not have an "environment" property.');
	}
	if (!environment.jwt) {
		throw Error('settings file does not have an "environment.jwt" property.');
	}

	let privateKeyContent;

	/* check the privateKey DEPRECATED
	if (fs.existsSync(integration.privateKey)) {
		privateKeyContent = fs.readFileSync(integration.privateKey);
	} else {
		throw Error("Private Key file does not exist at that location.");
	}
	*/

	// Honestly have no idea what to do here. Launch requires an OAuth2 Client Credentials grant.
	// Tried using passportjs but it was not intuitive.
	// There is an AdobeStrategy but it's 6 years old (uses Adobe IMS v1; current version is 3)
	// @see https://github.com/adobe/passport-adobe-oauth2/blob/master/lib/passport-adobe-oauth2/strategy.js
	// I could try and fork this strategy to make it work for v3 but at this point I'm not willing to sink any
	// more time into it.
	const clientId = integration.clientId;
	const clientSecret = integration.clientSecret;
	const old_scope = "AdobeID,openid,read_organizations,additional_info.job_function,additional_info.projectedProductContext,additional_info.roles";

	const tokenUrl = "https://ims-na1.adobelogin.com/ims/token/v3";

	const response = await fetch(tokenUrl, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
		},
		body: new URLSearchParams({
			grant_type: "client_credentials",
			client_id: clientId,
			client_secret: clientSecret,
			scope: "AdobeID,openid,read_organizations,additional_info.job_function,additional_info.projectedProductContext,additional_info.roles",
		}),
	});

	if (!response.ok) {
		throw new Error(`Error fetching access token: ${response.statusText}`);
	}

	const data = await response.json();
	return data.access_token;
};
