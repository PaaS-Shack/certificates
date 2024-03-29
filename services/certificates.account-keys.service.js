"use strict";

const acme = require('acme-client');
const DbService = require("db-mixin");
const ConfigLoader = require("config-mixin");
const { MoleculerClientError } = require("moleculer").Errors;


/**
 * service for managing acme account keys for Let's Encrypt and other ACME providers
 * 
 * @name v1.certificates.account-keys
 * @version 1.0.0
 * @fires "v1.certificates.account-keys.created"
 * @fires "v1.certificates.account-keys.updated"
 * @fires "v1.certificates.account-keys.removed"
 * @mixin DbService ConfigLoader
 */

module.exports = {
    // name of service
    name: "certificates.account-keys",
    // version of service
    version: 1,

    /**
     * Service Mixins
     * 
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
     */
    dependencies: [],

    /**
     * Service settings
     * 
     * @type {Object}
     */
    settings: {
        rest: true,

        fields: {
            environment: {
                type: "enum",
                default: "production",
                values: ["production", "staging"]
            },
            provider: {
                type: "enum",
                default: "letsencrypt",
                values: ["letsencrypt"]
            },
            email: {
                type: "string",
                required: true,
                trim: true,
                empty: false,
            },
            accountKey: {
                type: "string",
                required: true,
            },

            // account
            account: {
                type: "object",
                required: false,
            },


            ...DbService.FIELDS,// inject dbservice fields
        },

        // default database populates
        defaultPopulates: [],

        // database scopes
        scopes: {
            ...DbService.SCOPE,// inject dbservice scope
        },

        // default database scope
        defaultScopes: [...DbService.DSCOPE],// inject dbservice dscope

        // default init config settings
        config: {

        }
    },

    /**
     * service actions
     */
    actions: {
        // create a new account keys for a given email address
        // this will be used to create new certificates
        // then save the account key to the database
        createPrivateKey: {
            params: {
                email: { type: "string" },
                environment: {
                    type: "enum",
                    default: "production",
                    values: ["production", "staging"]
                },
                provider: {
                    type: "enum",
                    default: "letsencrypt",
                    values: ["letsencrypt"]
                }
            },
            async handler(ctx) {
                // get the email address
                const { email, environment, provider } = ctx.params;

                // lookup email environment and provider in database
                const found = await this.findByEmail(ctx, email, environment, provider);

                // if found return the account key record
                if (found)
                    throw new MoleculerClientError("Account key already exists", 409, "ACCOUNT_KEY_EXISTS", { email, environment, provider });

                if (provider == 'zerossl' && environment == 'staging')
                    throw new MoleculerClientError("Account key not supported for zerossl staging", 409, "ACCOUNT_KEY_NOT_SUPPORTED", { email, environment, provider });

                // get the provider config from acme module
                const directoryUrl = acme.directory[provider][environment];

                const accountKey = await acme.forge.createPrivateKey();

                // create the acme client
                const client = new acme.Client({
                    directoryUrl,
                    accountKey: accountKey
                });

                // create the account key
                const account = await client.createAccount({
                    termsOfServiceAgreed: true,
                    contact: [`mailto:${email}`],
                });

                // create the account key object
                const accountKeyObject = {
                    provider,
                    environment,
                    email,
                    accountKey,
                    account,
                };

                // save the account key to the database
                const accountKeyRecord = await this.createEntity(ctx, accountKeyObject);

                // return the account key record
                return accountKeyRecord;
            }
        },
        // retrieve the account key for a given email address, environment and provider
        getPrivateKey: {
            params: {
                email: { type: "string" },
                environment: {
                    type: "enum",
                    default: "production",
                    values: ["production", "staging"]
                },
                provider: {
                    type: "enum",
                    default: "letsencrypt",
                    values: ["letsencrypt"]
                }
            },
            async handler(ctx) {
                // get the email address
                const { email, environment, provider } = ctx.params;

                // lookup email environment and provider in database
                const found = await this.findByEmail(ctx, email, environment, provider);

                // if found return the account key record
                if (found)
                    return found;

                // if not found throw error
                throw new MoleculerClientError("Account key not found", 404, "ACCOUNT_KEY_NOT_FOUND", { email, environment, provider });
            }
        },
    },

    /**
     * service events
     */
    events: {

    },

    /**
     * service methods
     */
    methods: {
        findByEmail(ctx, email, environment, provider) {
            // find the account key record by email address
            return this.findEntity(null, {
                query: {
                    email: email,
                    environment: environment,
                    provider: provider,
                },
            });
        },
    }

}




