import { IAdminOpts } from '../daemon/admin/index.js';

export interface IConfig {
    nostr: {
        relays: string[];
    };
    admin: IAdminOpts;
    authPort?: number;
    authHost?: string;
    database: string;
    logs: string;
    verbose: boolean;
}
