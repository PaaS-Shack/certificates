"use strict";

const acme = require('acme-client');
const selfsigned = require('selfsigned');
const ConfigLoader = require("config-mixin");
const { MoleculerClientError } = require("moleculer").Errors;



/**
 * ACME service for managing certificates requests from Let's Encrypt and other ACME providers
 * @name v1.certificates.acme
 * @version 1.0.0
 */

module.exports = {
    // service name
    name: "certificates.acme",
    // service version
    version: 1,

    /**
     * Service Mixins
     * @type {Array}
     * @property {ConfigLoader} ConfigLoader - Config loader mixin
     * @property {DbService} DbService - Database mixin
     */
    mixins: [
        ConfigLoader(['certificates.**']),
    ],

    /**
     * Service dependencies
     * @type {Array}
     */
    dependencies: [],

    /**
     * Service settings
     * @type {Object} 
     */
    settings: {
        rest: true,

    },

    actions: {
        /**
         * Request a new certificate from Let's Encrypt and save it to the certificates service
         * 
         * @actions
         * @param {String} domain - Domain name
         * @param {Enum} environment - Environment production or staging
         * 
         * @returns {Object} Certificate
         * 
         * @example
         * Request a new certificate
         * 
         * POST /v1/certificates/acme/letsencrypt
         * 
         * {
         *   "domain": "example.com",
         *   "environment": "production"
         * }
         */
        letsencrypt: {
            rest: {
                method: "POST",
                path: "/letsencrypt"
            },
            permissions: ['certificates.acme.letsencrypt'],
            params: {
                domain: { type: "string" },// fqdn 
                environment: {
                    type: "enum",
                    values: ["production", "staging"],
                    optional: true,
                    default: "production"
                }
            },
            async handler(ctx) {
                const params = ctx.params;

                // resolve the domainObnject from the domain
                const domainObnject = await ctx.call('v1.domains.resolveDomain', { domain: params.domain });

                // if domain not found throw error
                if (!domainObnject)
                    throw new MoleculerClientError("Domain not found", 404, "DOMAIN_NOT_FOUND", { domain: params.domain });

                // get domain owner email
                const email = await ctx.call('v1.accounts.resolve', { id: domainObnject.owner, fields: ['email'] }).then((user) => user.email);
                const environment = params.environment;

                // request a new certificate from Let's Encrypt
                const cert = await this.letsencrypt(ctx, domainObnject, params.domain, email, environment);

                // create the certificate object
                const certificate = {
                    domain: fqdn,
                    email,
                    environment,
                    type: "letsencrypt",
                    cert: cert.cert,
                    privkey: cert.key,
                    chain: cert.chain,
                    expiresAt: this.getExpirationDate(cert.cert)
                }

                // save the certificate to the certificates service
                const savedCertificate = await ctx.call("v1.certificates.create", certificate);

                this.logger.info(`Certificate created for ${params.domain} ${email} ${environment}`);

                return savedCertificate;
            }
        },

        /**
         * Generate new selfsigned certificate and save it to the certificates service 
         * 
         * @actions
         * @param {String} domain - Domain name
         * @param {Enum} environment - Environment production or staging
         * 
         * @returns {Object} Certificate
         */
        selfsigned: {
            rest: {
                method: "POST",
                path: "/selfsigned"
            },
            permissions: ['certificates.acme.selfsigned'],
            params: {
                domain: { type: "string" },// fqdn
                environment: { type: "enum", values: ["production", "staging"] }
            },
            async handler(ctx) {
                const params = ctx.params;

                // resolve the domainObnject from the domain
                const domainObnject = await ctx.call('v1.domains.resolveDomain', { domain: params.domain });

                // if domain not found throw error
                if (!domainObnject)
                    throw new MoleculerClientError("Domain not found", 404, "DOMAIN_NOT_FOUND", { domain: params.domain });

                // get domain owner email
                const email = await ctx.call('v1.accounts.resolve', { id: domainObnject.owner, fields: ['email'] }).then((user) => user.email);
                const environment = params.environment;

                // request a new certificate from Let's Encrypt
                const cert = await this.selfsigned(ctx, domainObnject, params.domain, email, environment);

                // create the certificate object
                const certificate = {
                    domain: fqdn,
                    email,
                    environment,
                    type: "selfsigned",
                    cert: cert.cert,
                    privkey: cert.key,
                    chain: cert.chain,
                    expiresAt: this.getExpirationDate(cert.cert)
                }

                // save the certificate to the certificates service
                const savedCertificate = await ctx.call("v1.certificates.create", certificate);

                this.logger.info(`Certificate created for ${params.domain} ${email} ${environment}`);

                return savedCertificate;
            }
        },

        /**
         * Revoke a certificate
         * 
         * @actions
         * @param {String} id - Certificate id
         * 
         * @returns {Object} Certificate revoked
         */
        revoke: {
            rest: {
                method: "POST",
                path: "/revoke"
            },
            permissions: ['certificates.acme.revoke'],
            params: {
                id: { type: "string" }
            },
            async handler(ctx) {
                const params = ctx.params;

                // get certificate by id
                const cert = await ctx.call("v1.certificates.get", { id: params.id });

                // if certificate not found throw error
                if (!cert)
                    throw new MoleculerClientError("Certificate not found", 404, "CERTIFICATE_NOT_FOUND", { id: params.id });

                // revoke the certificate
                const revoked = await this.revoke(ctx, cert.cert, cert.email, cert.environment);

                // remove the certificate from the certificates service
                const removed = await ctx.call("v1.certificates.remove", { id: params.id });

                this.logger.info(`Certificate removed/revoked for ${cert.email} ${cert.environment}`);

                return removed;
            }
        },

        /**
         * Renew a certificate
         * 
         * @actions
         * @param {String} id - Certificate id
         * 
         * @returns {Object} Certificate renewed
         */
        renew: {
            rest: {
                method: "POST",
                path: "/renew"
            },
            permissions: ['certificates.acme.renew'],
            params: {
                id: { type: "string" }
            },
            async handler(ctx) {
                const params = ctx.params;

                // get certificate by id
                const cert = await ctx.call("v1.certificates.get", { id: params.id });

                // if certificate not found throw error
                if (!cert)
                    throw new MoleculerClientError("Certificate not found", 404, "CERTIFICATE_NOT_FOUND", { id: params.id });

                // get domain object
                const domainObject = await ctx.call('v1.domains.resolveDomain', { domain: cert.domain });

                // if domain not found throw error
                if (!domainObject)
                    throw new MoleculerClientError("Domain not found", 404, "DOMAIN_NOT_FOUND", { domain: cert.domain });

                // get domain owner email
                const email = await ctx.call('v1.accounts.resolve', { id: domainObnject.owner, fields: ['email'] }).then((user) => user.email);
                const environment = cert.environment;

                // create the certificate object
                const certificate = {
                    domain: cert.domain,
                    email,
                    environment,
                    type: cert.type,
                }
                //test for letsencrypt or selfsigned
                if (cert.type == "letsencrypt") {
                    // request a new certificate from Let's Encrypt
                    const newCert = await this.letsencrypt(ctx, domainObnject, cert.domain, email, environment);

                    // update the certificate object
                    certificate.cert = newCert.cert;
                    certificate.privkey = newCert.key;
                    certificate.chain = newCert.chain;
                    certificate.expiresAt = this.getExpirationDate(newCert.cert);
                } else if (cert.type == "selfsigned") {
                    // request a new certificate from Let's Encrypt
                    const newCert = await this.selfsigned(ctx, domainObnject, cert.domain, email, environment);

                    // update the certificate object
                    certificate.cert = newCert.cert;
                    certificate.privkey = newCert.key;
                    certificate.chain = newCert.chain;
                    certificate.expiresAt = this.getExpirationDate(newCert.cert);
                }
                // remove the old certificate from the certificates service
                const removedID = await ctx.call("v1.certificates.remove", { id: params.id });

                this.logger.info(`Certificate ${removedID} removed for ${cert.email} ${cert.environment}`);

                // save the new certificate to the certificates service
                const savedCertificate = await ctx.call("v1.certificates.create", certificate);

                this.logger.info(`Certificate ${savedCertificate.id} renewed for ${params.domain} ${email} ${environment}`);

                return savedCertificate;
            }
        }
    },

    /**
     * Events
     * @type {Object}
     */
    events: {},

    /**
     * Methods
     * @type {Object}
     */
    methods: {
        /**
         * Create a selfsigned certificate and return it
         */
        async selfsigned(ctx, domain, environment) {

            // create a selfsigned certificate
            const cert = selfsigned.generate([{
                name: 'commonName',
                value: domain
            }], {
                algorithm: 'sha256',
                days: 30,
                keySize: 2048,
                extensions: [{
                    name: 'basicConstraints',
                    cA: true
                }]
            });

            return {
                cert: cert.cert,
                privkey: cert.private,
                chain: cert.public,
            }
        },

        /**
        * Request a new certificate from Let's Encrypt through DNS challenge
        * 
        * @param {Object} ctx - Context
        * @param {Object} domainObject - Domain object
        * @param {String} fqdn - Fully qualified domain name
        * @param {String} email - Email address
        * @param {Enum} environment - Environment production or staging
        * 
        * @returns {Object} Certificate
        */
        async letsencrypt(ctx, domainObject, fqdn, email, environment) {


            // get account key
            const accountKey = await this.getAccountKey(ctx, email, environment, "letsencrypt");
            const directoryUrl = environment === "production" ? acme.directory.letsencrypt.production : acme.directory.letsencrypt.staging;

            // create the acme client
            const client = new acme.Client({
                directoryUrl,
                accountKey
            });

            // create the certificate signing request
            const [key, csr] = await acme.forge.createCsr({
                commonName: fqdn
            });

            const cert = await client.auto({
                csr,
                email,
                termsOfServiceAgreed: true,
                challengeCreateFn: async (authz, challenge, keyAuthorization) => {
                    const fqdn = authz.identifier.value;
                    const data = keyAuthorization;

                    this.logger.info(`challengeCreateFn ${domainObject.domain} ${email} ${environment} ${fqdn} ${data}`);

                    const record = await this.addDnsRecord(ctx, domainObject.id, fqdn, data);

                    await this.waitForRecord(ctx, fqdn, data);

                    return record;
                },
                challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
                    const fqdn = authz.identifier.value;
                    const data = keyAuthorization;

                    this.logger.info(`challengeRemoveFn ${domainObject.domain} ${email} ${environment} ${fqdn} ${data}`);

                    const record = await this.removeDnsRecord(ctx, domainObject.id, fqdn, data);

                    return record;
                }
            });

            return {
                key: key.toString(),
                chain: csr.toString(),
                cert: cert.toString(),
            };
        },

        /**
         * Revoke a certificate through the acme client
         * 
         * @param {Object} ctx - Context
         * @param {String} cert - Certificate
         * @param {String} email - Email address
         * @param {Enum} environment - Environment production or staging
         * 
         * @returns {Object} Certificate
         */
        async revoke(ctx, cert, email, environment) {
            // get account key
            const accountKey = await this.getAccountKey(ctx, email, environment, "letsencrypt");
            const directoryUrl = environment === "production" ? acme.directory.letsencrypt.production : acme.directory.letsencrypt.staging;

            // create the acme client
            const client = new acme.Client({
                directoryUrl,
                accountKey
            });

            // revoke the certificate
            const revoked = await client.revoke({
                certificate: cert
            });
            this.logger.info(`Certificate revoked for ${email} ${environment}`);

            return revoked;
        },

        /**
         * Get account key
         * if account key does not exist, create a new one
         * 
         * @param {Object} ctx - Context
         * @param {String} email - Email address
         * @param {Enum} environment - Environment production or staging
         * @param {Enum} provider - Provider letsencrypt
         * 
         * @returns {String} Account key
         * 
         * @example
         * Get account key
         */
        async getAccountKey(ctx, email, environment, provider) {

            // lookup email environment and provider at service v1.certificates.account-keys
            const accountKey = await ctx.call("v1.certificates.account-keys.getPrivateKey", {
                email, environment, provider
            });

            // if account key found return the account key
            if (accountKey) {
                this.logger.info(`Account key found for ${email} ${environment} ${provider}`);
                return accountKey;
            }

            // create new account key at service v1.certificates.account-keys
            const newAccountKey = await ctx.call("v1.certificates.account-keys.createPrivateKey", {
                email, environment, provider
            });

            this.logger.info(`Account key created for ${email} ${environment} ${provider}`);

            // return the new account key
            return newAccountKey.privkey;
        },

        /**
         * Add DNS record through the domains.records service
         * 
         * @param {Object} ctx - Context
         * @param {String} domainID - Domain id
         * @param {String} fqdn - Record name
         * @param {String} data - Record TXT value
         * @param {Enum} type - Record type
         * 
         * @returns {Object} Record
         */
        async addDnsRecord(ctx, domain, fqdn, data, type = "TXT") {
            const record = await ctx.call("v1.domains.records.create", {
                domain, fqdn, type, data
            });
            this.logger.info(`${domain} adding TXT record for ${fqdn}`, record);
            return record;
        },

        /**
         * Remove DNS record through the domains.records service
         * 
         * @param {Object} ctx - Context
         * @param {String} domainID - Domain id
         * @params {String} recordID - Record id
         * 
         * @returns {String} Record id
         */
        async removeDnsRecord(ctx, domain, record) {
            const recordID = await ctx.call("v1.domains.records.remove", {
                domain,
                id: record.id
            });

            this.logger.info(`${domain} removing TXT record for ${record.fqdn}`, record);

            return recordID;
        },

        /**
         * Wait for record to be propagated through the v1.resolver service
         * once magority of dns servers responce with fulfilled and has txt value in value array, 
         * return true or timeout
         * 
         * @param {Object} ctx - Context
         * @param {String} fqdn - Record name
         * @param {String} data - Record TXT value
         * @param {Enum} type - Record type
         * 
         * @returns {Bootlean} Record has propagated
         */
        async waitForRecord(ctx, fqdn, data, type = "TXT") {

            const startTime = new Date();

            while (true) {
                const results = await ctx.call("v1.resolver.propagation", {
                    fqdn, type
                });

                const fulfilled = results.filter(result => result.status === "fulfilled");


                // if majority of dns servers have fulfilled status 
                //and has txt value in value array, return true
                if (fulfilled.length > results.length / 2 && fulfilled.some(result => result.value.includes(data))) {
                    this.logger.info(`TXT record for ${fqdn} has propagated took ${(new Date() - startTime) / 1000} seconds`);
                    return true;
                }

                const currentTime = new Date();
                const timeElapsed = (currentTime - startTime) / 1000;

                if (timeElapsed > 120) {
                    this.logger.info(`Timeout waiting for ${fqdn} to propagate`);
                    return false;
                }

                await this.sleep(1000);
            }

        },

        /**
         * Sleep for a given time
         * 
         * @param {Number} ms - Time in milliseconds
         * 
         * @returns {Promise} Promise
         */
        sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        },

        /**
         * Get the domain name from the certificate
         * 
         * @param {String} cert - Certificate
         * 
         * @returns {String} Domain name
         */
        getDomainName(cert) {
            const domainName = cert.match(/CN=([^\/]+)/)[1];
            return domainName;
        },

        /**
         * Get the certificate expiration date
         * 
         * @param {String} cert - Certificate
         * 
         * @returns {Date} Expiration date
         */
        getExpirationDate(cert) {
            const expirationDate = cert.match(/Not After : (.*)/)[1];
            return new Date(expirationDate);
        },




    },
};
