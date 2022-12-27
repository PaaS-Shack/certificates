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

				if (false) {

					await this.removeEntity(null, {
						id: certs.id
					})

					ctx.broadcast('certificates.update', result)
				}
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
		async challengeRemove(ctx, domain, authz, challenge, keyAuthorization) {
			console.log('challengeRemove')
			const fqdn = `_acme-challenge.${authz.identifier.value}`;
			const data = keyAuthorization;
			const record = await ctx.call('v1.domains.records.find', {
				domain: domain.id,
				query: {
					fqdn,
					type: "TXT",
					data,
				}
			}).then((res) => res.shift())

			this.logger.info(`${domain.domain} removing TXT record for ${fqdn}`, record)

			await ctx.call('v1.domains.records.remove', { id: record.id }).then(console.log).catch(console.log);

			return this.sleep(1000)
		},
		async challengeCreate(ctx, domain, authz, challenge, keyAuthorization) {

			const fqdn = `_acme-challenge.${authz.identifier.value}`;
			const data = keyAuthorization;
			const record = {
				domain: domain.id,
				fqdn,
				type: "TXT",
				data,
			}

			this.logger.info(`${domain.domain} Creating TXT record for ${fqdn}`)

			await ctx.call('v1.domains.records.create', record).then(console.log).catch(console.log);
			return this.sleep(1000)
		},
		sleep(time) {
			return new Promise((resolve) => {
				setTimeout(resolve, time)
			});
		},
		vHostParts(vHost) {

			var parts = vHost.split('.');
			var result = [parts.join('.')];
			var n;
			// Prevent abusive lookups
			while (parts.length > 6) {
				parts.shift();
			}
			while (parts.length > 1) {
				parts.shift();
				n = parts.join('.');
				result.push('*.' + n);
			}
			result.push('*');

			return result;
		},
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