const _ = require('lodash');
const crypto = require('crypto');
const URL = require('url');

class Akamai_EdgeAuth_ParameterException extends Error { }

class Akamai_EdgeAuth_Config {
    constructor() {
        this.algo = "sha256";
        this.ip = '';
        this.start_time = 0;
        this.window = 300;
        this.acl = '';
        this.url = '';
        this.session_id = '';
        this.data = '';
        this.salt = '';
        this.key = 'aabbccddeeff00112233445566778899';
        this.field_delimiter = '~';
        this.early_url_encoding = false;
    }

    encode(val) {
        if (this.early_url_encoding === true) {
            return rawurlencode(val);
        }
        return val;
    }

    set_algo(algo) {
        if (['sha256', 'sha1', 'md5'].indexOf(algo) >= 0) {
            this.algo = algo;
        } else {
            throw new Akamai_EdgeAuth_ParameterException("Invalid algorithme, must be one of 'sha256', 'sha1' or 'md5'");
        }
    }

    get_algo() {
        return this.algo;
    }

    set_ip(ip) {
        // @TODO: Validate IPV4 & IPV6 addrs
        this.ip = ip;
    }

    get_ip() {
        return this.ip;
    }

    get_ip_field() {
        if (this.ip != "") {
            return 'ip=' + this.ip + this.field_delimiter;
        }
        return "";
    }

    set_start_time(start_time) {
        // verify starttime is sane
        if (start_time.toLowerCase && start_time.toLowerCase() === "now") {
            this.start_time = Math.floor(Date.now() / 1000);
        } else {
            if (start_time > 0 && start_time < 4294967295) {
                this.start_time = Number(start_time); // faster then intval
            } else {
                throw new Akamai_EdgeAuth_ParameterException("start time input invalid or out of range");
            }
        }
    }

    get_start_time() {
        return this.start_time;
    }

    get_start_time_value() {
        if (this.start_time > 0) {
            return this.start_time;
        } else {
            return Math.floor(Date.now() / 1000);
        }
    }

    get_start_time_field() {
        if (this.start_time > 0 && this.start_time < 4294967295) {
            return 'st=' + this.get_start_time_value() + this.field_delimiter;
        } else {
            return '';
        }
    }

    set_window(window) {
        // verify window is sane
        if (window > 0) {
            this.window = Number(window); // faster then intval
        } else {
            throw new Akamai_EdgeAuth_ParameterException("window input invalid");
        }
    }

    get_window() {
        return this.window;
    }

    get_expr_field() {
        return 'exp=' + (this.get_start_time_value() + this.window) + this.field_delimiter;
    }

    set_acl(acl) {
        if (this.url != "") {
            throw new Akamai_EdgeAuth_ParameterException("Cannot set both an ACL and a URL at the same time");
        }
        this.acl = acl;
    }

    get_acl() {
        return this.acl;
    }

    get_acl_field() {
        if (this.acl) {
            return 'acl=' + this.encode(this.acl) + this.field_delimiter;
        } else if (!this.url) {
            //return a default open acl
            return 'acl=' + this.encode('/*') + this.field_delimiter;
        }
        return '';
    }

    set_url(url) {
        if (this.acl) {
            throw new Akamai_EdgeAuth_ParameterException("Cannot set both an ACL and a URL at the same time");
        }
        this.url = url;
    }

    get_url() {
        return this.url;
    }

    get_url_field() {
        if (this.url && !this.acl) {
            return 'url=' + this.encode(this.url) + this.field_delimiter;
        }
        return '';
    }

    set_session_id(session_id) {
        this.session_id = session_id;
    }

    get_session_id() {
        return this.session_id;
    }

    get_session_id_field() {
        if (this.session_id) {
            return 'id=' + this.session_id + this.field_delimiter;
        }
        return "";
    }

    set_data(data) {
        this.data = data;
    }

    get_data() {
        return this.data;
    }

    get_data_field() {
        if (this.data) {
            return 'data=' + this.data + this.field_delimiter;
        }
        return "";
    }

    set_salt(salt) {
        this.salt = salt;
    }

    get_salt() {
        return this.salt;
    }

    get_salt_field() {
        if (this.salt) {
            return 'salt=' + this.salt + this.field_delimiter;
        }
        return "";
    }

    set_key(key) {
        //verify the key is valid hex
        if (key.match(/^[a-fA-F0-9]+$/) && (key.length % 2) == 0) {
            this.key = key;
        } else {
            throw new Akamai_EdgeAuth_ParameterException("Key must be a hex string (a-f,0-9 and even number of chars)");
        }
    }

    get_key() {
        return this.key;
    }

    set_field_delimiter(field_delimiter) {
        this.field_delimiter = field_delimiter;
    }

    get_field_delimiter() {
        return this.field_delimiter;
    }

    set_early_url_encoding(early_url_encoding) {
        this.early_url_encoding = early_url_encoding;
    }

    get_early_url_encoding() {
        return this.early_url_encoding;
    }
}

class Akamai_EdgeAuth_Generate {

    h2b(str) {
        let b = new Buffer.alloc(str.length / 2);
        let i = 0;
        do {
            const octet = str.substr(i, 2);
            const ascii = parseInt(octet, 16);
            b.writeUInt8(ascii, i / 2);
            i += 2;
        } while (i < str.length);

        return b;
    }

    generate_token(config) {
        // ASSUMES:($algo='sha256', $ip='', $start_time=null, $window=300, $acl=null, $acl_url="", $session_id="", $payload="", $salt="", $key="000000000000", $field_delimiter="~")
        let m_token = config.get_ip_field();
        m_token += config.get_start_time_field();
        m_token += config.get_expr_field();
        m_token += config.get_acl_field();
        m_token += config.get_session_id_field();
        m_token += config.get_data_field();
        let m_token_digest = m_token;
        m_token_digest += config.get_url_field();
        m_token_digest += config.get_salt_field();

        // produce the signature and append to the tokenized string
        const hmac = crypto.createHmac(config.get_algo(), this.h2b(config.get_key()));
        hmac.update(m_token_digest.replace(new RegExp("\\" + config.get_field_delimiter() + "$"), ""), 'ascii');
        const signature = hmac.digest('hex');
        return m_token + 'hmac=' + signature;
    }
}

// https://flosports.akamaized.net/hls/live/2009442/fd13576s_geo_block/playlist.m3u8
//      ?hdnea=st=1585325156~exp=1585411556~acl=/hls/live/2009442/fd13576s_geo_block/playlist.m3u8~hmac=99d08efb966cdc1a2d9ae9d646a68724e9c912c0e5463b4196e05bea5c2f0b3c

function Akamai_EdgeAuth_Validate(configIn, tokenParam, url) {
    const parsedUrl = new URL.URL(url);
    const token = parsedUrl.searchParams.get(tokenParam);

    const attributeList = token.split(configIn.get_field_delimiter());
    const attributes = attributeList.reduce((accum, curr) => {
        const [k, v] = curr.split('=');
        accum[k] = v;
        return accum;
    }, {});

    // Check the ACL and expiration first.  No point going through the
    // trouble of checking the signature if the ACL is wrong.
    if (attributes.exp < Math.floor(Date.now() / 1000))
        throw 'Token expired';

    // Convert the wildcards to regex, but first escape any other chars
    // that might be seen as regex
    let regex = attributes.acl.replace(/[-[\]{}()+.,\\^$|#\\s]/g, '\\$&');
    regex = regex.replace(/\*/g, '.*');
    regex = regex.replace(/\?/g, '[^/]+');

    if (!RegExp(`^${regex}$`).test(parsedUrl.pathname))
        throw 'Invalid URL path';

    // Check the signature
    const configOut = new Akamai_EdgeAuth_Config();
    configOut.set_field_delimiter(configIn.get_field_delimiter());
    configOut.set_algo(configIn.get_algo());
    configOut.set_key(configIn.get_key());
    configOut.set_early_url_encoding(configIn.get_early_url_encoding());
    configOut.set_start_time(attributes.st);
    configOut.set_window(+attributes.exp - +attributes.st);
    if (attributes.ip)
        configOut.set_ip(attributes.ip);
    if (attributes.id)
        configOut.set_session_id(attributes.id);
    if (attributes.data)
        configOut.set_data(attributes.data);
    if (attributes.acl)
        configOut.set_acl(attributes.acl);
    if (attributes.url)
        configOut.set_url(attributes.url);

    const tokenOut = new Akamai_EdgeAuth_Generate().generate_token(configOut);

    if (token != tokenOut)
        throw 'Invalid Token';
}

module.exports = {
    Akamai_EdgeAuth_Config: Akamai_EdgeAuth_Config,
    Akamai_EdgeAuth_Generate: Akamai_EdgeAuth_Generate,
    Akamai_EdgeAuth_Validate: Akamai_EdgeAuth_Validate
}

// CLI Parameter Control
if (process.argv.indexOf('token') > -1) {
    if (process.argv.length > 2) {
        const help = "node token [options...]\n" +
            "\n" +
            "Options:\n" +
            "\n" +
            "-i IP_ADDRESS, --ip=IP_ADDRESS\t\tIP Address to restrict this token to.\n" +
            "-s START_TIME, --start-time=START_TIME\tWhat is the start time. (Use now for the current time)\n" +
            "-w SECONDS, --window=SECONDS\t\tHow long is this token valid for?\n" +
            "-u URL, --url=URL\t\t\tURL path. [Used for:URL]\n" +
            "-a ACCESS_LIST, --acl=ACCESS_LIST\tAccess control list delimited by ! [ie. /*]\n" +
            "-k KEY, --key=KEY\t\t\tSecret required to generate the token.\n" +
            "-p PAYLOAD, --payload=PAYLOAD\t\tAdditional text added to the calculated digest.\n" +
            "-A ALGORITHM, --algo=ALGORITHM\t\tAlgorithm to use to generate the token. (sha1, sha256,\n" +
            "\t\t\t\t\tor md5) [Default:sha256]\n" +
            "-S SALT, --salt=SALT\t\t\tAdditional data validated by the token but NOT included in the token body.\n" +
            "-I SESSION_ID, --session_id=SESSION_ID\tThe session identifier for single use tokens or other advanced cases.\n" +
            "-d FIELD_DELIMITER, --field_delimiter=FIELD_DELIMITER\n" +
            "\t\t\t\t\tCharacter used to delimit token body fields. [Default:~]\n" +
            "-D ACL_DELIMITER, --acl_delimiter=ACL_DELIMITER\n" +
            "\t\t\t\t\tCharacter used to delimit acl fields. [Default:!]\n" +
            "-x, --escape_early\t\t\tCauses strings to be url encoded before being used. (legacy 2.0 behavior)\n" +
            "\n" +
            "Examples:\n" +
            "\n" +
            "node token --start-time:now --window:86400\n";

        const opt = require('node-getopt').create([
            ['h', 'help'],
            ['i', 'ip=ARG'],
            ['s', 'start-time=ARG'],
            ['a', 'acl=ARG'],
            ['e', '=ARG'],
            ['w', 'window=ARG'],
            ['u', 'url=ARG'],
            ['k', 'key=ARG'],
            ['p', 'payload=ARG'],
            ['A', 'algo=ARG'],
            ['S', 'salt=ARG'],
            ['I', 'session-id=ARG'],
            ['d', 'field-delimiter=ARG'],
            ['D', 'acl-delimiter=ARG'],
            ['X', ''],
            ['x', 'escape-early'],
            ['v', ''],
        ])
            .bindHelp(help)
            .parseSystem();

        const c = new Akamai_EdgeAuth_Config();
        const g = new Akamai_EdgeAuth_Generate();

        _.forOwn(opt.options, function (v, o) {
            if ((o == 'help') || (o == 'h')) {
                //@TODO
                exit(0);
            } else if ((o == 'window') || (o == 'w')) {
                c.set_window(v);
            } else if ((o == 'start-time') || (o == 's')) {
                c.set_start_time(v);
            } else if ((o == 'ip') || (o == 'i')) {
                c.set_ip(v);
            } else if ((o == 'acl') || (o == 'a')) {
                c.set_acl(v);
            } else if ((o == 'session-id') || (o == 'I')) {
                c.set_session_id(v);
            } else if ((o == 'payload') || (o == 'p')) {
                c.set_data(v);
            } else if ((o == 'url') || (o == 'u')) {
                c.set_url(v);
            } else if ((o == 'salt') || (o == 'S')) {
                c.set_salt(v);
            } else if ((o == 'field-delimiter') || (o == 'd')) {
                c.set_field_delimiter(v);
            } else if ((o == 'acl-delimiter') || (o == 'D')) {
                //@TODO
            } else if ((o == 'algo') || (o == 'A')) {
                c.set_algo(v);
            } else if ((o == 'key') || (o == 'k')) {
                c.set_key(v);
            } else if (o == 'debug') {
                //@TODO
            } else if ((o == 'escape-early') || (o == 'x')) {
                c.set_early_url_encoding(true);
            }
        });

        const token = g.generate_token(c);
        console.log(token);
    } else {
        console.log('try "node token --help" for more information');
    }
}
