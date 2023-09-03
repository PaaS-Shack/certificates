"use strict";

const DbService = require("db-mixin");
const ConfigLoader = require("config-mixin");
const { MoleculerClientError } = require("moleculer").Errors;
const forge = require('node-forge');

//const Lock = require("../mixins/lock");


/**
 * Service for managing certificates
 * @name v1.certificates
 * @version 1.0.0
 * @fires "v1.certificates.created"
 * @fires "v1.certificates.updated"
 * @fires "v1.certificates.removed"
 * @mixin ConfigLoader 
 * @mixin DbService 
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
		rest: true,//enable rest endpoints

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
			keySelector: {
				type: "string",
				required: false,
				trim: true,
				empty: false,
			},
			expiresAt: {
				type: "number",
				required: false,
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
		// extend the default actions
		...DbService.ACTIONS,

		// disable rest endpoint for create action
		create: { rest: false },

		/**
		 * Get a list of expiring certificates
		 * 
		 * @actions
		 * @param {number} days - Number of days to look into the future
		 * 
		 * @returns {Array} - Array of certificates
		 */
		getExpiring: {
			rest: {
				method: "GET",
				path: "/expiring"
			},
			params: {
				days: { type: "number", default: 30, optional: true },
			},
			permissions: ['certificates.expiring'],
			async handler(ctx) {
				const params = Object.assign({}, ctx.params);

				// get the date in the future
				const now = new Date();
				const expiresAt = new Date(now.getTime() + (params.days * 24 * 60 * 60 * 1000));

				// find all certificates that expire before the given date
				const found = await this.findEntities(null, {
					query: {
						expiresAt: { $lte: expiresAt }
					},
					fields: ['id', 'createdAt', 'domain', 'environment', 'type', 'expiresAt']
				});

				return found.map((cert) => {
					cert.age = (Date.now() - (new Date(cert.createdAt))) / (1000 * 3600 * 24);
					cert.expiresIn = (cert.expiresAt - Date.now()) / (1000 * 3600 * 24);
					return cert;
				})
			}
		},

		/**
		 * Renew expiring certificates
		 * 
		 * @actions
		 * @param {number} days - Number of days to look into the future
		 * 
		 * @returns {Array} - Array of renewed certificates
		 */
		renewExpiring: {
			rest: {
				method: "GET",
				path: "/renew-expiring"
			},
			params: {
				days: { type: "number", default: 30, optional: true },
			},
			permissions: ['certificates.renew'],
			async handler(ctx) {
				const params = Object.assign({}, ctx.params);

				//use action getExpiring to get a list of expiring certificates
				const expiring = await ctx.call('v1.certificates.getExpiring', params);

				// renew all expiring certificates
				const renewed = await Promise.all(expiring.map(async (cert) => {
					const renewed = await ctx.call('v1.certificates.acme.renew', { id: cert.id });
					return renewed;
				}));

				return renewed;
			}
		},

		/**
		 * Resolve most recent certificate for a domain
		 * If no certificate is found, create one
		 * 
		 * @actions
		 * @param {string} domain - Domain to resolve
		 * @param {string} environment - Environment to resolve
		 * @param {string} type - Type of certificate to resolve
		 * 
		 * @returns {Object} - Certificate
		 */
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

				//if autoGenerate false throw error
				if (this.config['certificates.autoGenerate'] === false) {
					throw new MoleculerClientError('Certificate not found.', 400, 'ERR_CERTIFICATE_NOT_FOUND', { params });
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

		/**
		 * Certificate details
		 * 
		 * @actions
		 * @param {string} id - ID of the certificate
		 * 
		 * @returns {Object} - Certificate details
		 */
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


				// Parse the certificate
				const certificate = forge.pki.certificateFromPem(cert.cert);

				// get the certificate details
				const details = {
					issuer: certificate.issuer,
					subject: certificate.subject,
					validity: certificate.validity,
					serialNumber: certificate.serialNumber,
					extensions: certificate.extensions,
					...certificate.siginfo,
				}

				return details;
			}
		},

		/**
		 * Resolve dkim keys for a domain
		 * if no keys are found, create them
		 * 
		 * @actions
		 * @param {string} domain - Domain to resolve
		 * @param {string} environment - Environment to resolve
		 * 
		 * @returns {Object} - DKIM keys
		 */
		resolveDKIM: {
			cache: false,
			params: {
				domain: { type: "string", min: 3, optional: false },
				keySelector: { type: "string", min: 3, default: 'default', optional: true },
			},
			permissions: ['certificates.resolveDKIM'],
			async handler(ctx) {
				const params = Object.assign({}, ctx.params);

				const found = await this.findEntity(null, {
					query: {
						domain: params.domain,
						keySelector: params.keySelector,
						type: 'dkim'
					},
					sort: ['-createdAt'],
				});

				if (found) {
					found.age = (Date.now() - (new Date(found.createdAt))) / (1000 * 3600 * 24);
					return found;
				}

				//if autoGenerate false throw error
				if (this.config['certificates.autoGenerate'] === false) {
					throw new MoleculerClientError('Certificate not found.', 400, 'ERR_CERTIFICATE_NOT_FOUND', { params });
				}

				// if the certificate is not found, create one
				return ctx.call('v1.certificates.dkim', {
					domain: params.domain,
					keySelector: params.keySelector
				})
			}
		},

		/**
		 * Create dkim keys for a domain
		 * 
		 * @actions
		 * @param {string} domain - Domain to resolve
		 * @param {string} environment - Environment to resolve
		 * 
		 * @returns {Object} - DKIM keys
		 */
		dkim: {
			params: {
				domain: { type: "string", min: 3, optional: false },
				keySelector: { type: "string", min: 3, default: 'default', optional: true },
			},
			permissions: ['certificates.dkim'],
			async handler(ctx) {
				const params = Object.assign({}, ctx.params);

				// Generate a DKIM key pair
				const dkim = await this.generateDKIM(params.domain, params.keySelector);

				// save the dkim keys
				const saved = await this.createEntity(null, dkim);

				// return the saved dkim keys
				return saved;
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
		/**
		 * Generate dkim keys for a domain
		 * 
		 * @param {string} domain - Domain to resolve
		 * @param {string} keySelector - Key selector to use
		 * 
		 * @returns {Promise} - DKIM keys
		 */
		async generateDKIM(domain, keySelector) {
			const dkimKeys = await dkim.generateKey({
				domainName: domain,
				keySelector, // You can choose a key selector here
				privateKeyLength: 2048, // You can adjust the key length as needed
			});

			const dkim = {
				domain,
				keySelector,
				type: 'dkim',
				privkey: dkimKeys.privateKey,
				chain: dkimKeys.publicKey,
				cert: dkimKeys.publicKey,
				email: 'postmaster@' + domain,
				expiresAt: Date.now() + (1000 * 3600 * 24 * 365 * 10),
			};

			return dkim;
		},
		// promisify setTimeout
		sleep(time) {
			return new Promise((resolve) => {
				setTimeout(resolve, time)
			});
		},

		/**
		 * Split a vHost into parts
		 * 
		 * @param {String} vHost 
		 * 
		 * @returns {Array} - Array of vHost parts
		 */
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

		/**
		 * Find a certificate by id in the database
		 * 
		 * @param {Object} ctx - Context
		 * @param {String} domain - Domain ID to find
		 * 
		 * @returns {Object} - Certificate
		 */
		findByID(ctx, id) {
			return this.resolveEntity(null, {
				id
			})
		},

		/**
		 * Find a certificate by domain in the database
		 * most recently used for type and environment
		 * 
		 * @param {Object} ctx - Context
		 * @param {String} domain - FQDN to find
		 * @param {String} type - Type to find letsencrypt or selfsigned
		 * @param {String} environment - Environment to find staging or production
		 * 
		 * @returns {Object} - Certificate
		 */
		findByDomain(ctx, domain, type, environment) {
			return this.findEntity(null, {
				query: {
					domain,
					type,
					environment
				},
				sort: ['-createdAt'],

			})
		},

		/**
		 * seed the config sore with default config values
		 * 
		 * @returns {Promise} - Promise
		 */
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
