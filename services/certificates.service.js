"use strict";

const DbService = require("db-mixin");
const ConfigLoader = require("config-mixin");
const { MoleculerClientError } = require("moleculer").Errors;
const certinfo = require('cert-info');

//const Lock = require("../mixins/lock");


/**
 * Service for managing certificates
 * @name v1.certificates
 * @version 1.0.0
 * @fires "v1.certificates.created"
 * @fires "v1.certificates.updated"
 * @fires "v1.certificates.removed"
 * @mixin DbService ConfigLoader
 */
module.exports = {
	// name of service
	name: "certificates",
	// version of service
	version: 1,

	/**
	 * Service Mixins
	 * @type {Array}
	 * @property {DbService} DbService - Database mixin
	 * @property {ConfigLoader} ConfigLoader - Config loader mixin
	 */
	mixins: [
		DbService({}),
		ConfigLoader(['certificates.**']),
	],

	/**
	 * Service dependencies 
	 * @type {Array}
	 */
	dependencies: [],

	/**
	 * Service settings
	 */
	settings: {
		rest: true,

		fields: {
			privkey: {
				type: "string",
				required: true,
				trim: true,
				empty: false,
				secure: true,
			},
			chain: {
				type: "string",
				required: true,
				trim: true,
				empty: false,
			},
			cert: {
				type: "string",
				required: true,
				trim: true,
				empty: false,
			},
			domain: {
				type: "string",
				required: true,
				trim: true,
				empty: false,
			},
			email: {
				type: "string",
				required: true,
				trim: true,
				empty: false,
			},
			owner: {
				type: "string",
				required: false,
				trim: true,
				empty: false,
			},
			environment: {
				type: "string",
				required: true,
				trim: true,
				empty: false,
			},
			type: {
				type: "string",
				required: true,
				trim: true,
				empty: false,
			},

			...DbService.FIELDS
		},

		defaultPopulates: [],

		scopes: {
			...DbService.SCOPE
		},

		defaultScopes: [...DbService.DSCOPE],

		config: {
			"certificates.autoGenerate": false,// generate certificates automatically
		}
	},

	/**
	 * Actions
	 */
	actions: {
		...DbService.ACTIONS,

		create: { rest: false },
		// get a list of expiring certificates that are older than 60 days
		getExpiring: {
			async handler(ctx) {


				const days90 = Date.now() - 7.776e+9
				const days60 = Date.now() - 5.184e+9
				const days30 = Date.now() - 2.592e+9

				const certs = await this.findEntities(null, {
					query: {
						createdAt: { $gte: days90 }
					},
					fields: ['id', 'createdAt', 'domain', 'environment']
				}, { raw: true });

				return certs.filter((entity) => {
					entity.age = (Date.now() - (new Date(entity.createdAt))) / (1000 * 3600 * 24);
					return entity.age > 60;
				});
			}
		},
		// get a list of expiring certificates that are older than 60 days
		listExpiring: {
			async handler(ctx) {

				const days90 = Date.now() - 7.776e+9
				const days60 = Date.now() - 5.184e+9
				const days30 = Date.now() - 2.592e+9

				const certs = await this.findEntities(null, {
					query: {
						createdAt: { $gte: days90 }
					},
					fields: ['id', 'createdAt', 'domain', 'environment']
				}, { raw: true });

				return certs.map((entity) => {
					entity.age = (Date.now() - (new Date(entity.createdAt))) / (1000 * 3600 * 24);
					return entity;
				})
			}
		},
		// replaces create action rest endpoint
		// with one that points to the letsencrypt dns action
		requestCert: {
			rest: 'POST /',
			params: {
				domain: { type: "string", min: 3, optional: false },
				environment: { type: "enum", default: 'production', values: ["staging", "production"], optional: true },
			},
			async handler(ctx) {
				const params = Object.assign({}, ctx.params);

				return ctx.call('v1.certificates.letsencrypt.dns', {
					domain: params.domain,
					environment: params.environment
				})

			}
		},
		// updated expiring certificates with new ones
		updateExpiring: {
			params: {},
			async handler(ctx) {
				const expiringCerts = await this.actions.getExpiring({}, { parentCtx: ctx });

				return Promise.allSettled(expiringCerts.map((expiring) =>
					ctx.call('v1.certificates.letsencrypt.dns', {
						domain: expiring.domain
					})
				));
			}
		},

		// resolves a domain to a certificate or creates one
		resolveDomain: {
			cache: false,
			params: {
				domain: { type: "string", min: 3, optional: false },
				environment: { type: "enum", default: 'production', values: ["staging", "production"], optional: true },
				type: { type: "enum", default: 'letsencrypt', values: ["selfsigned", "letsencrypt"], optional: true },
			},
			permissions: ['certificates.get'],
			auth: "required",
			async handler(ctx) {
				const params = Object.assign({}, ctx.params);

				const found = await this.findEntity(null, {
					query: {
						domain: params.domain,
						environment: params.environment,
						type: params.type
					},
					fields: ['id', 'createdAt', 'domain', 'environment', 'type']
				});

				if (found) {
					found.age = (Date.now() - (new Date(found.createdAt))) / (1000 * 3600 * 24);
					return found;
				}

				// if the certificate is not found, create one
				if (params.type == 'letsencrypt') {
					return ctx.call('v1.certificates.letsencrypt.dns', {
						domain: params.domain,
						environment: params.environment
					})
				}

				// if the certificate is not found, create one
				if (params.type == 'selfsigned') {
					return ctx.call('v1.certificates.selfsigned', {
						domain: params.domain,
						environment: params.environment
					})
				}

				// no certificate type found throw an error
				throw new MoleculerClientError('Unknown certificate type', 400, 'UNKNOWN_CERTIFICATE_TYPE', { params });
			}
		},

		// action to return details information about a certificate
		// info like the certificate singed by, the domain, the owner, etc.
		details: {
			params: {
				id: { type: "string", min: 3, optional: false },
			},
			permissions: ['certificates.details'],
			async handler(ctx) {
				const params = Object.assign({}, ctx.params);

				const cert = await this.findByID(ctx, params.id);

				if (!cert)
					throw new MoleculerClientError("Certificate not found.", 400, "ERR_CERTIFICATE_NOT_FOUND");

				// get the details of the certificate
				const details = certinfo.info(cert.cert);

				return {
					...details
				};
			}
		}
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
		// promisify setTimeout
		sleep(time) {
			return new Promise((resolve) => {
				setTimeout(resolve, time)
			});
		},
		// split the vHost into parts and return an array of possible vHosts
		// www.example.com -> [ 'www.example.com', '*.example.com' ]
		vHostParts(vHost) {
			const parts = vHost.split('.')
			const result = []

			for (let index = 0; index < parts.length; index++) {
				const part = parts[index];
				// skip the first part of the domain
				const subdomain = parts.slice(index + 1).join('.')
				result.push(vHost)
				// skip the wildcard
				if (part != '*')
					result.push('*.' + subdomain)
			}

			return result;
		},
		findByID(ctx, id) {
			return this.findEntity(null, {
				query: { id },
			});
		},
		// seed the config sore with default config values
		async seedDB() {
			for (const [key, value] of Object.entries(this.settings.config || {})) {
				const found = await this.broker.call('v1.config.get', { key });
				if (found == null) {
					await this.broker.call('v1.config.set', { key, value });
				}
			}
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
