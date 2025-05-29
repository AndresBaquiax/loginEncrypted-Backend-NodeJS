import crypto from 'crypto';

// Clave pública RSA
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlCiXfuXt8L26Ja3bX0eS
FbkGXjepVGQL4Oct4FGWOW6u1KoWHCYvKLdbJZMoRO8osD4AZURHK27PSluAS2rt
UA3Bk+I57xTeqle/y9+Cic/U/7GrsUYgsau711peYAFKrdIC1xFEloMWhbq9yGl8
flJ36IN4dixUB8eO0FuHiLC/ZwKlc/B66lsbZqgBHMJ36h9a8wCFPGn0swBXW0+7
dA1nDf3wJrvX9UTK+cOdqyepbF0+H/csbbwcHmggTh1oZMpWmhoCmF9kQXcpiLWT
JkeiL+VYIBCO+MVyWDobckKYK4XNXuQz6g0VQJCuhjh2csL0EQen6Rq7j9FuuBFJ
RQIDAQAB
-----END PUBLIC KEY-----`;

// Variables específicas que necesitas cifrar
const variables = {
    SECRET_KEY: 'f6e11bffbb342444ce15c240fb7aa588a9dfd2b84706a3a0b5035b78f8ee38f090b63ed992af97f48c2c2b1f9b83af7824abe254be1d7e43c7123d920ce0c52a',
    PORT: '4000',
    DB_USER: 'postgres',
    DB_PASSWORD: 'root',
    DB_SERVER: 'localhost',
    DB_DATABASE: 'hashing',
    DB_PORT: '5432'
};

function cifrarRSA(texto) {
    const buffer = Buffer.from(texto, 'utf8');
    const encrypted = crypto.publicEncrypt({
        key: PUBLIC_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, buffer);
    return encrypted.toString('base64');
}

console.log('=== VARIABLES CIFRADAS RSA ===');
console.log('Copia estas líneas a tu .env:\n');

console.log(`SECRET_KEY_RSA=${cifrarRSA(variables.SECRET_KEY)}`);
console.log(`PORT_RSA=${cifrarRSA(variables.PORT)}`);
console.log(`DB_USER_RSA=${cifrarRSA(variables.DB_USER)}`);
console.log(`DB_PASSWORD_RSA=${cifrarRSA(variables.DB_PASSWORD)}`);
console.log(`DB_SERVER_RSA=${cifrarRSA(variables.DB_SERVER)}`);
console.log(`DB_DATABASE_RSA=${cifrarRSA(variables.DB_DATABASE)}`);
console.log(`DB_PORT_RSA=${cifrarRSA(variables.DB_PORT)}`); 