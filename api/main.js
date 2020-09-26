const express = require('express')
const http = require('http')
const mongo = require('mongodb')
const MongoClient = mongo.MongoClient
const uuid = require('uuid').v4
const spawnSync = require('child_process').spawnSync
const nodemailer = require('nodemailer')
const fs = require('fs')

////////////////////////////////////////////////////////////////////////////////
// Global Constants
////////////////////////////////////////////////////////////////////////////////

const MONGO_URL = 'mongodb://localhost:27017'
const DATABASE = 'certificateSigningRequestsDB'
const COLLECTION = 'certificateSigningRequests'
const PORT = 8003
const LOG_OPTIONS = {
    'color': true,
    'depth': null,
}
const EMAIL_DOMAIN_WHITELIST = [
    'durfee.io',
]
const TRANSPORTER = nodemailer.createTransport({
    'service': 'gmail',
    'auth': {
        'user': 'robert.durfee.17@gmail.com',
        'pass': process.env.GMAIL_APP_PASSWORD,
    },
})
const STATUS_CODE_OK = 200
const STATUS_CODE_BAD_REQUEST = 400
const STATUS_CODE_NOT_FOUND = 404
const STATUS_CODE_INTERNAL_SERVER_ERROR = 500
const STATUS_BAD_REQUEST = 'BAD_REQUEST'
const STATUS_NOT_FOUND = 'NOT_FOUND'
const STATUS_INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR'
const STATUS_PENDING = 'PENDING'
const STATUS_VERIFIED = 'VERIFIED'
const STATUS_FAILED = 'FAILED'
const STATUS_MESSAGE_PENDING = 'Pending email verification. Please check your inbox.'
const STATUS_MESSAGE_VERIFIED = 'Email address has been verified. Certificate signing request has been granted.'
const STATUS_MESSAGE_FAILED = 'The certificate signing request has been denied.'

////////////////////////////////////////////////////////////////////////////////
// Global Variables
////////////////////////////////////////////////////////////////////////////////

var db

////////////////////////////////////////////////////////////////////////////////
// Helper Functions
////////////////////////////////////////////////////////////////////////////////

const extractCSRSubject = csr => {
    return spawnSync('openssl', [ 'req', '-noout', '-subject' ], { input: csr, encoding: 'utf-8' }).stdout.slice(8).split(',').map(sp => {
        return sp.trim().split('=')
    }).reduce((kvs, [k, v]) => {
        return { [(k || '').trim().toLowerCase()]: (v || '').trim(), ...kvs }
    }, {})
}

const validEmailAddress = emailAddress => {
    const eap = (emailAddress || '').split('@')
    if ((eap.length == 2) && (EMAIL_DOMAIN_WHITELIST.includes(eap[1]))) {
        return true
    } else {
        return false
    }
}

const sign = emailAddress => {
    return spawnSync('openssl', [ 'ca', '-batch', '-config', '/root/ca/intermediate/openssl.cnf', '-extensions', 'usr_cert', '-days', '375', '-notext', '-md', 'sha256', '-passin', `pass:${process.env.CA_INTERMEDIATE_PASSWORD}`, '-in', `/root/ca/intermediate/csr/${emailAddress}.csr.pem`, '-out', `/root/ca/intermediate/certs/${emailAddress}.cert.pem` ], { 'encoding': 'utf-8' })
}

////////////////////////////////////////////////////////////////////////////////
// App Configuration
////////////////////////////////////////////////////////////////////////////////

const app = express()

app.use(express.json())
app.set('json spaces', 2)

////////////////////////////////////////////////////////////////////////////////
// REST Methods
////////////////////////////////////////////////////////////////////////////////

// Method: certificateSigningRequests.insert
app.post('/certificateSigningRequests', (req, res) => {
    const id = uuid()
    console.dir({
        'id': id,
        'request': {
            'method': req['method'],
            'url': req['url'],
            'params': req['params'],
            'query': req['query'],
            'body': req['body'],
        }
    }, LOG_OPTIONS)
    const subject = extractCSRSubject(req.body['csr'])
    if (!validEmailAddress(subject['emailaddress'])) {
        const body = {
            'error': {
                'code': STATUS_CODE_BAD_REQUEST,
                'message': `Email address '${subject['emailaddress']}' is not valid.`,
                'status': STATUS_BAD_REQUEST,
            }
        }
        res.status(STATUS_CODE_BAD_REQUEST).json(body)
        console.dir({
            'id': id,
            'response': {
                'statusCode': res['statusCode'],
                'statusMessage': res['statusMessage'],
                'body': body,
            }
        }, LOG_OPTIONS)
        return
    }
    fs.writeFileSync(`/root/ca/intermediate/csr/${subject['emailaddress']}.csr.pem`, req.body['csr'], { mode: 0o444 })
    const now = new Date()
    const verificationCode = uuid()
    TRANSPORTER.sendMail({
        'from': 'Durfee Certificate Authority <noreply-ca@durfee.io>',
        'to': subject['emailaddress'],
        'subject': 'Email Verification',
        'text': `Verification code: ${verificationCode}.`,
    }).then(() => {
        return db.collection(COLLECTION).insertOne({
            'createdAt': now,
            'modifiedAt': now,
            'accessedAt': now,
            'csr': req.body['csr'],
            'status': STATUS_PENDING,
            'statusMessage': STATUS_MESSAGE_PENDING,
            'cert': '',
            'verificationCode': verificationCode,
        })
    }).then(result => {
        if (result.insertedCount == 1) {
            const body = {
                'id': `${result.ops[0]['_id']}`,
                'createdAt': result.ops[0]['createdAt'],
                'modifiedAt': result.ops[0]['modifiedAt'],
                'accessedAt': result.ops[0]['accessedAt'],
                'csr': result.ops[0]['csr'],
                'status': result.ops[0]['status'],
                'statusMessage': result.ops[0]['statusMessage'],
            }
            res.status(STATUS_CODE_OK).json(body)
            console.dir({
                'id': id,
                'response': {
                    'statusCode': res['statusCode'],
                    'statusMessage': res['statusMessage'],
                    'body': body,
                }
            }, LOG_OPTIONS)
        } else {
            const body = {
                'error': {
                    'code': STATUS_CODE_INTERNAL_SERVER_ERROR,
                    'message': `Unexpected error occurred when inserting resource: Unexpected number of inserted resources: ${result.insertedCount}`,
                    'status': STATUS_INTERNAL_SERVER_ERROR,
                }
            }
            res.status(STATUS_CODE_INTERNAL_SERVER_ERROR).json(body)
            console.dir({
                'id': id,
                'response': {
                    'statusCode': res['statusCode'],
                    'statusMessage': res['statusMessage'],
                    'body': body,
                }
            }, LOG_OPTIONS)
        }
    }).catch(error => {
        const body = {
            'error': {
                'code': STATUS_CODE_INTERNAL_SERVER_ERROR,
                'message': `Unexpected error occurred when inserting resource: ${error.message}`,
                'status': STATUS_INTERNAL_SERVER_ERROR,
            }
        }
        res.status(STATUS_CODE_INTERNAL_SERVER_ERROR).json(body)
        console.dir({
            'id': id,
            'response': {
                'statusCode': res['statusCode'],
                'statusMessage': res['statusMessage'],
                'body': body,
            }
        }, LOG_OPTIONS)
    })
})

// Method: certificateSigningRequests.verify
app.post('/certificateSigningRequests/:resourceId/verify', (req, res) => {
    const id = uuid()
    console.dir({
        'id': id,
        'request': {
            'method': req['method'],
            'url': req['url'],
            'params': req['params'],
            'query': req['query'],
            'body': req['body'],
        }
    }, LOG_OPTIONS)
    const now = new Date()
    var resourceId
    try {
        resourceId = mongo.ObjectId(req.params['resourceId'])
    } catch (error) {
        const body = {
            'error': {
                'code': STATUS_CODE_BAD_REQUEST,
                'message': `Resource ID '${req.params['resourceId']}' is malformed: ${error.message}`,
                'status': STATUS_BAD_REQUEST,
            }
        }
        res.status(STATUS_CODE_BAD_REQUEST).json(body)
        console.dir({
            'id': id,
            'response': {
                'statusCode': res['statusCode'],
                'statusMessage': res['statusMessage'],
                'body': body,
            }
        }, LOG_OPTIONS)
        return
    }
    db.collection(COLLECTION).findOneAndUpdate({
        '_id': resourceId,
    }, {
        '$set': {
            'accessedAt': now,
        },
    }).then(result => {
        if (result.value) {
            if (result.value['verificationCode'] == req.body['verificationCode']) {
                const subject = extractCSRSubject(result.value['csr'])
                sign(subject['emailaddress'])
                const cert = fs.readFileSync(`/root/ca/intermediate/certs/${subject['emailaddress']}.cert.pem`, { 'encoding': 'utf-8' })
                return db.collection(COLLECTION).findOneAndUpdate({
                    '_id': resourceId,
                }, {
                    '$set': {
                        'modifiedAt': now,
                        'status': STATUS_VERIFIED,
                        'statusMessage': STATUS_MESSAGE_VERIFIED,
                        'cert': cert,
                    }
                }).then(result => {
                    if (result.value) {
                        const body = {
                            'id': `${result.value['_id']}`,
                            'createdAt': result.value['createdAt'],
                            'modifiedAt': now,
                            'accessedAt': now,
                            'csr': result.value['csr'],
                            'status': STATUS_VERIFIED,
                            'statusMessage': STATUS_MESSAGE_VERIFIED,
                            'cert': cert,
                        }
                        res.status(STATUS_CODE_OK).json(body)
                        console.dir({
                            'id': id,
                            'response': {
                                'statusCode': res['statusCode'],
                                'statusMessage': res['statusMessage'],
                                'body': body,
                            }
                        }, LOG_OPTIONS)
                    } else {
                        const body = {
                            'error': {
                                'code': STATUS_CODE_NOT_FOUND,
                                'message': `Resource '${req.params['resourceId']}' was not found.`,
                                'status': STATUS_NOT_FOUND,
                            }
                        }
                        res.status(STATUS_CODE_NOT_FOUND).json(body)
                        console.dir({
                            'id': id,
                            'response': {
                                'statusCode': res['statusCode'],
                                'statusMessage': res['statusMessage'],
                                'body': body,
                            }
                        }, LOG_OPTIONS)
                    }
                })
            } else {
                const body = {
                    'error': {
                        'code': STATUS_CODE_BAD_REQUEST,
                        'message': `Verification code '${req.body['verificationCode']}' is incorrect.`,
                        'status': STATUS_BAD_REQUEST,
                    }
                }
                res.status(STATUS_CODE_BAD_REQUEST).json(body)
                console.dir({
                    'id': id,
                    'response': {
                        'statusCode': res['statusCode'],
                        'statusMessage': res['statusMessage'],
                        'body': body,
                    }
                }, LOG_OPTIONS)
            }
        } else {
            const body = {
                'error': {
                    'code': STATUS_CODE_NOT_FOUND,
                    'message': `Resource '${req.params['resourceId']}' was not found.`,
                    'status': STATUS_NOT_FOUND,
                }
            }
            res.status(STATUS_CODE_NOT_FOUND).json(body)
            console.dir({
                'id': id,
                'response': {
                    'statusCode': res['statusCode'],
                    'statusMessage': res['statusMessage'],
                    'body': body,
                }
            }, LOG_OPTIONS)
        }
    }).catch(error => {
        const body = {
            'error': {
                'code': STATUS_CODE_INTERNAL_SERVER_ERROR,
                'message': `Unexpected error occurred when verifying resource '${req.params['resourceId']}': ${error.message}`,
                'status': STATUS_INTERNAL_SERVER_ERROR,
            }
        }
        res.status(STATUS_CODE_INTERNAL_SERVER_ERROR).json(body)
        console.dir({
            'id': id,
            'response': {
                'statusCode': res['statusCode'],
                'statusMessage': res['statusMessage'],
                'body': body,
            }
        }, LOG_OPTIONS)
    })
})

////////////////////////////////////////////////////////////////////////////////
// Connect
////////////////////////////////////////////////////////////////////////////////

MongoClient.connect(MONGO_URL, { useUnifiedTopology: true }).then(client => {
    db = client.db(DATABASE)
    http.createServer(app).listen(PORT)
}).catch(error => {
    console.error(error)
    process.exit(1)
})

