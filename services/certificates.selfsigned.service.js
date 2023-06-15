"use strict";
const selfsigned = require('selfsigned');
const DbService = require("db-mixin");
const ConfigLoader = require("config-mixin");
const { MoleculerClientError } = require("moleculer").Errors;

//const Lock = require("../mixins/lock");


/**
 * Addons service
 */
module.exports = {
	name: "certificates.selfsigned",
	version: 1,

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
		rest: true,
	},

	/**
	 * Actions
	 */
	actions: {
		generate: {
			params: {
				domain: { type: "string", min: 3, optional: false },
				force: { type: "boolean", default: false, optional: true },
				environment: { type: "enum", default: 'production', values: ["staging", "production"], optional: true },
			},
			permissions: ['certificates.create'],
			async handler(ctx) {

				const params = Object.assign({}, ctx.params);
				const domain = await ctx.call('v1.domains.resolveDomain', { domain: params.domain })
				const email = await ctx.call('v1.accounts.get', { id: domain.owner, fields: ['email'] }).then((user) => user.email)

				const environment = params.environment

				if (!domain) {
					this.logger.info(`${params.domain} Not managed by v1.domains service`)
					return null;
				}


				this.logger.info(`${params.domain} ${email} Challenging ${environment} environment`)

				const pems = selfsigned.generate([{ name: 'commonName', value: params.domain }], { days: 95 });


				/* Done */
				this.logger.info(`CSR:\n${pems.public.toString()}`);
				this.logger.info(`Private key:\n${pems.private.toString()}`);
				this.logger.info(`Certificate:\n${pems.cert.toString()}`);
				const entity = {};

				entity.privkey = pems.private.toString();
				entity.chain = pems.public.toString();
				entity.cert = pems.cert.toString();

				entity.domain = params.domain;
				entity.email = email;
				entity.environment = environment;
				entity.type = 'selfsigned';


				const result = await ctx.call('v1.certificates.create', entity)

				this.logger.info(`${params.domain} ${email} Challenge successful ${new Date(result.createdAt)} ${result.id}`)

				return result;
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