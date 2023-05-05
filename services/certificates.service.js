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
		DbService({

		}),
		ConfigLoader(['certificates.**']),
		//Lock('certificates', {})
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
		},
		defaultPopulates: [],
		scopes: {},
		defaultScopes: [],
		config: {
			"certificates.autoGenerate": false
		}
	},

	/**
	 * Actions
	 */
	actions: {

		create: {
			rest: false,
			permissions: ['certificates.create']
		},
		list: {
			permissions: ['certificates.list']
		},
		find: {
			rest: "GET /find",
			permissions: ['certificates.find']
		},
		count: {
			rest: "GET /count",
			permissions: ['certificates.count']
		},
		get: {
			needEntity: true,
			permissions: ['certificates.get']
		},
		update: {
			needEntity: true,
			permissions: ['certificates.update']
		},
		replace: false,
		remove: {
			needEntity: true,
			permissions: ['certificates.remove']
		},
		getExpiring: {
			params: {

			},
			async handler(ctx) {
				return this.findEntities(null, {
					query: {},
					fields: ['id', 'createdAt', 'domain', 'environment']
				}).then((res) => res.map((entity) => {
					entity.createdAt = new Date(entity.createdAt);
					entity.age = (Date.now() - entity.createdAt.getTime()) / (1000 * 3600 * 24);
					return entity;
				}).filter((entity) => entity.age > 60));
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
					this.actions.dns({
						domain: expiring.domain
					}, { parentCtx: ctx })
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
