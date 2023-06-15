"use strict";

const acme = require('acme-client');
const DbService = require("db-mixin");
const ConfigLoader = require("config-mixin");
const { MoleculerClientError } = require("moleculer").Errors;

const Lock = require("../lib/lock");


/**
 * Addons service
 */
module.exports = {
	name: "certificates.letsencrypt",
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

			...DbService.FIELDS

		},
		defaultPopulates: [],

		scopes: {
			...DbService.SCOPE
		},

		defaultScopes: [...DbService.DSCOPE]
	},

	/**
	 * Actions
	 */
	actions: {
		...DbService.ACTIONS,
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
			},
			permissions: ['certificates.get'],
			auth: "required",
			async handler(ctx) {
				const params = Object.assign({}, ctx.params);
				const parts = this.vHostParts(params.domain)

				const environment = params.environment

				let cert
				for (let index = 0; index < parts.length; index++) {
					const domain = parts[index];
					let certs = await this.findEntity(null, {
						query: { domain, environment },
						sort: ['-createdAt'],
						limit: 1
					})
					if (certs)
						return certs
				}
				if (this.config['certificates.autoGenerate']) {
					let certs;
					if (await this.lock.isLocked(params.domain)) {
						await this.lock.acquire(params.domain)
						certs = await this.findEntity(null, {
							query: { domain, environment },
							sort: ['-createdAt'],
							limit: 1
						})
						await this.lock.release(params.domain)
					} else {
						await this.lock.acquire(params.domain)
						certs = await this.actions.dns(params, { parentCtx: ctx })
						await this.lock.release(params.domain)
					}

					return certs;
				}
				throw new MoleculerClientError("certificates not found.", 400, "ERR_EMAIL_EXISTS");
			}
		},
		dns: {
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

				// let certs = await this.findEntity(ctx, {
				// 	query: { domain: params.domain, environment },
				// 	sort: ['-createdAt'],
				// 	limit: 1
				// })

				// if (!params.force && certs && (Date.now() - certs.createdAt) < 30 * 24 * 60 * 1000) {
				// 	this.logger.info(`${params.domain} Resolving old certificate`)
				// 	return certs
				// }

				this.logger.info(`${params.domain} ${email} Challenging ${environment} environment`)

				const accountKey = await acme.forge.createPrivateKey()

				this.logger.info(`${params.domain} ${email} accountKey`)

				const client = new acme.Client({
					directoryUrl: acme.directory.letsencrypt[environment],
					accountKey
				});

				/* Create CSR */
				const [key, csr] = await acme.forge.createCsr({
					commonName: params.domain
				});

				this.logger.info(`${params.domain} ${email} Create CSR`)
				/* Certificate */
				const cert = await client.auto({
					challengePriority: ['dns-01'],
					csr,
					email,
					termsOfServiceAgreed: true,
					challengeCreateFn: (authz, challenge, keyAuthorization) => this.challengeCreate(ctx, domain, authz, challenge, keyAuthorization),
					challengeRemoveFn: (authz, challenge, keyAuthorization) => this.challengeRemove(ctx, domain, authz, challenge, keyAuthorization)
				}).catch((err) => {
					console.log(err)
					throw err;
				});

				/* Done */
				this.logger.info(`CSR:\n${csr.toString()}`);
				this.logger.info(`Private key:\n${key.toString()}`);
				this.logger.info(`Certificate:\n${cert.toString()}`);
				const entity = {};

				entity.privkey = key.toString();
				entity.chain = csr.toString();
				entity.cert = cert.toString();

				entity.domain = params.domain;
				entity.email = email;
				entity.environment = environment;
				entity.type = 'letsencrypt';

				const result = await ctx.call('v1.certificates.create', entity)
				//const result = await this.createEntity(ctx, entity, { permissive: true });;

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
			}, {
				meta: { userID: domain.owner }
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

			await ctx.call('v1.domains.records.create', record, {
				meta: { userID: domain.owner }
			}).then(console.log).catch(console.log);
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
		this.lock = new Lock()
	},

	/**
	 * Service stopped lifecycle event handler
	 */
	stopped() { }
};