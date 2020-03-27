const AkamaiToken = require('./token');

function assertFail(func) {
    try {
        func();
        throw 'assertion failed';
    }
    catch (e) {
    }
}

const testKey = '11223344556677889900';

function generateTestUrl(acl, startTime) {
    const config = new AkamaiToken.Akamai_EdgeAuth_Config();
    config.set_start_time(startTime || 'now');
    config.set_window(300);
    config.set_acl(acl);
    config.set_key(testKey);

    const hmac = new AkamaiToken.Akamai_EdgeAuth_Generate().generate_token(config);

    return 'https://foo.bar.com/path/to/file.m3u8?hdnea=' + hmac;
}

const config = new AkamaiToken.Akamai_EdgeAuth_Config();
config.set_key(testKey);

// Testing happy path
AkamaiToken.Akamai_EdgeAuth_Validate(config, 'hdnea', generateTestUrl('/path/to/file.m3u8'));

// Testing ACL with wildcards
AkamaiToken.Akamai_EdgeAuth_Validate(config, 'hdnea', generateTestUrl('/*/file.m3u8'));
AkamaiToken.Akamai_EdgeAuth_Validate(config, 'hdnea', generateTestUrl('/?/?/file.m3u8'));
AkamaiToken.Akamai_EdgeAuth_Validate(config, 'hdnea', generateTestUrl('/path/*'));

assertFail(() => AkamaiToken.Akamai_EdgeAuth_Validate(config, 'hdnea', generateTestUrl('/?/file.m3u8')));
assertFail(() => AkamaiToken.Akamai_EdgeAuth_Validate(config, 'hdnea', generateTestUrl('/*/xfile.m3u8')));

// Testing expired token
assertFail(() => AkamaiToken.Akamai_EdgeAuth_Validate(config, 'hdnea',
    generateTestUrl('/path/to/file.m3u8', Math.floor(Date.now() - 500000) / 1000)));
