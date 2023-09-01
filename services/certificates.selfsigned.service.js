"use strict";
const selfsigned = require('selfsigned');
const DbService = require("db-mixin");
const ConfigLoader = require("config-mixin");
const { MoleculerClientError } = require("moleculer").Errors;

//const Lock = require("../mixins/lock");


/**
 * service
 * @name v1.certificates.selfsigned
 * @version 1.0.0
 * @fires "v1.certificates.selfsigned.created"
 * @fires "v1.certificates.selfsigned.updated"
 * @fires "v1.certificates.selfsigned.removed"
 * @mixin DbService ConfigLoader
 */
module.exports = {
	// name of service
	name: "certificates.selfsigned",
	// version of service
	version: 1,
	/**
	 * Service Mixins
	 * @type {Array}
	 * @property {ConfigLoader} ConfigLoader - Config loader mixin
	 */
	mixins: [
		ConfigLoader(['certificates.**']),
	],

	/**
	 * Service dependencies
	 */
	dependencies: [],

	/**
	 * Service settings
	 */
	settings: {
		rest: true,// Expose as REST API
	},

	/**
	 * Actions
	 */
	actions: {
		// Create a new certificate for a domain
		// 
		generate: {
			rest: {
				method: "POST",
				path: "/generate",
			},
			params: {
				domain: { type: "string", min: 3, optional: false },
				force: { type: "boolean", default: false, optional: true },
				environment: { type: "enum", default: 'production', values: ["staging", "production"], optional: true },
			},
			permissions: ['certificates.selfsigned.generate'],
			async handler(ctx) {
				const params = Object.assign({}, ctx.params);

				const domain = params.domain;
				const force = params.force;
				const environment = params.environment;

				const domainObject = await ctx.call('v1.domains.resolveDomain', { domain: params.domain });
				if (!domainObject)
					throw new MoleculerClientError("Domain not found.", 400, "ERR_DOMAIN_NOT_FOUND");

				const user = await ctx.call('v1.accounts.get', { id: domainObject.owner, fields: ['email'] });


				const cert = await this.findByDomain(ctx, domain);

				if (cert && !force) {
					this.logger.info(`Certificate for domain '${domain}' already exists.`);
					return cert;
				}

				const attrs = [{
					name: 'commonName',
					value: domain
				}, {
					name: 'countryName',
					value: 'US'
				}, {
					shortName: 'ST',
					value: 'Virginia'
				}, {
					name: 'localityName',
					value: 'Blacksburg'
				}, {
					name: 'organizationName',
					value: 'Test'
				}, {
					shortName: 'OU',
					value: 'Test'
				}];
				const pems = selfsigned.generate(attrs, {
					keySize: 2048, // the size for the private key in bits (default: 1024)
					days: 360, // how long till expiry of the signed certificate (default: 365)
					algorithm: 'sha256', // sign the certificate with specified algorithm (default: 'sha1')
					extensions: [{ name: 'basicConstraints', cA: true }], // certificate extensions array
					pkcs7: true, // include PKCS#7 as part of the output (default: false)
					clientCertificate: false, // generate client cert signed by the original key (default: false)
					clientCertificateCN: user.username	 // client certificate's common name (default: 'John Doe jdoe123')
				});


				const certData = {
					privkey: pems.private,
					cert: pems.cert,
					chain: pems.cert + '\n' + pems.private,// make a chain with the cert and the private key
					domain,
					environment,
					email: user.email,
					type: 'selfsigned',
					owner: domainObject.owner,
				};

				const created = await ctx.call('v1.certificates.create', certData);;

				this.logger.info(`Certificate for domain '${domain}' created.`);

				return created;
			}
		},
	},

	/**
	 * Events
	 */
	events: {

	},

	/**
	 * Methods
	 */
	methods: {
		findByDomain(ctx, domain) {
			return ctx.call('v1.certificates.find', { query: { domain } }).then((res) => {
				return res.shift();
			});
		}
	},

	/**
	 * Service created lifecycle event handler
	 */
	created() { },

	/**
	 * Service started lifecycle event handler
	 */
	started() {

	},

	/**
	 * Service stopped lifecycle event handler
	 */
	stopped() { }
};