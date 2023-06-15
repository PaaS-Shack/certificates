"use strict";

const acme = require('acme-client');
const DbService = require("db-mixin");
const ConfigLoader = require("config-mixin");
const { MoleculerClientError } = require("moleculer").Errors;

//const Lock = require("../mixins/lock");


/**
 * Addons service
 */
module.exports = {
	name: "certificates",
	version: 1,

	mixins: [
		DbService({}),
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
		rest: true,

		fields: {
			privkey: {
				type: "string",
				required: true,
				trim: true,
				empty: false,
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
			"certificates.autoGenerate": false
		}
	},

	/**
	 * Actions
	 */
	actions: {
		...DbService.ACTIONS,


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


				const map = new Map()

				for (let index = 0; index < certs.length; index++) {
					const cert = certs[index];

					cert.age = (Date.now() - (new Date(cert.createdAt))) / (1000 * 3600 * 24);

					if (map.has(cert.domain)) {
						const old = map.get(cert.domain)
						if (cert.createdAt > old.createdAt) {
							map.set(cert.domain, cert)
						}
					} else {
						map.set(cert.domain, cert)
					}
				}


				return Array.from(map.values()).filter((entity) => entity.age > 60);
			}
		},
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
		updateExpiring: {
			params: {

			},
			async handler(ctx) {
				const expiringCerts = await this.actions.getExpiring({}, { parentCtx: ctx })
				return Promise.allSettled(expiringCerts.map((expiring) =>
					ctx.call('v1.certificates.letsencrypt.dns', {
						domain: expiring.domain
					})
				));
			}
		},
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

				const parts = this.vHostParts(params.domain)

				const environment = params.environment
				const type = params.type

				let cert
				for (let index = 0; index < parts.length; index++) {
					const domain = parts[index];
					let certs = await this.findEntity(null, {
						query: { domain, environment, type },
						sort: ['-createdAt'],
						limit: 1
					})
					if (certs)
						return certs
				}
				return ctx.call('v1.certificates.letsencrypt.resolveDomain', params)

				throw new MoleculerClientError("certificates not found.", 400, "ERR_EMAIL_EXISTS");
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

		sleep(time) {
			return new Promise((resolve) => {
				setTimeout(resolve, time)
			});
		},
		vHostParts(vHost) {

			const parts = vHost.split('.');
			const result = [parts.join('.')];
			let n;

			parts.shift();
			n = parts.join('.');
			result.push('*.' + n);

			return result;
		},
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
