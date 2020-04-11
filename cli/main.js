const inquirer = require('inquirer')
const spawnSync = require('child_process').spawnSync
const fs = require('fs')
const https = require('https')

////////////////////////////////////////////////////////////////////////////////
// Global Constants
////////////////////////////////////////////////////////////////////////////////

const EMAIL_DOMAIN_WHITELIST = [
    'durfee.io',
]

////////////////////////////////////////////////////////////////////////////////
// Command-Line Arguments
////////////////////////////////////////////////////////////////////////////////

inquirer
    .prompt([
        {
            'type': 'input',
            'name': 'countryName',
            'message': 'Country Name (2 letter code):',
            'default': 'US',
        }, {
            'type': 'input',
            'name': 'stateName',
            'message': 'State or Province Name (full name):',
            'default': 'Wisconsin',
        }, {
            'type': 'input',
            'name': 'localityName',
            'message': 'Locality Name (eg, city):',
            'default': 'Waupaca',
        }, {
            'type': 'input',
            'name': 'organizationName',
            'message': 'Organization Name (eg, company):',
            'default': 'Durfee Ltd',
        }, {
            'type': 'input',
            'name': 'emailAddress',
            'message': 'Email Address:',
            'validate': emailAddress => {
                const eap = (emailAddress || '').split('@')
                return ((eap.length == 2) && (EMAIL_DOMAIN_WHITELIST.includes(eap[1])))
            }
        },
    ]).then(answers => {
        spawnSync('openssl', [ 'req', '-nodes', '-newkey', 'rsa:4096', '-keyout', `${answers['emailAddress']}.key.pem`, '-out', `${answers['emailAddress']}.csr.pem`, '-subj', `/C=${answers['countryName']}/ST=${answers['stateName']}/L=${answers['localityName']}/O=${answers['organizationName']}/CN=${answers['emailAddress']}/emailAddress=${answers['emailAddress']}` ], { 'encoding': 'utf-8' })
        const csr = fs.readFileSync(`${answers['emailAddress']}.csr.pem`, { 'encoding': 'utf-8' })
        const payload = JSON.stringify({
            'csr': csr
        })
        const request = https.request({
            'hostname': 'ca.durfee.io',
            'port': 443,
            'ca': fs.readFileSync('../ca.cert.pem'),
            'path': '/certificateSigningRequests',
            'method': 'POST',
            'headers': {
                'Content-Type': 'application/json',
                'Content-Length': payload.length,
            },
        }, response => {
            var body = ''
            response.on('data', data => {
                body = body + data
            })
            response.on('end', () => {
                if (response.statusCode == 200) {
                    if (body == '') {
                        console.error(`Unexpected response '${body}'`)
                        process.exit(1)
                    }
                    try {
                        body = JSON.parse(body)
                    } catch (error) {
                        console.error(error)
                        process.exit(1)
                    }
                    const id = body['id']
                    inquirer
                        .prompt([
                            {
                                'type': 'input',
                                'name': 'verificationCode',
                                'message': 'Verification Code:',
                            },
                        ]).then(verificationAnswers => {
                            const payload = JSON.stringify({
                                'verificationCode': verificationAnswers['verificationCode']
                            })
                            const request = https.request({
                                'hostname': 'ca.durfee.io',
                                'port': 443,
                                'ca': fs.readFileSync('../ca.cert.pem'),
                                'path': `/certificateSigningRequests/${id}/verify`,
                                'method': 'POST',
                                'headers': {
                                    'Content-Type': 'application/json',
                                    'Content-Length': payload.length,
                                }
                            }, response => {
                                var body = ''
                                response.on('data', data => {
                                    body = body + data
                                })
                                response.on('end', () => {
                                    if (response.statusCode == 200) {
                                        if (body == '') {
                                            console.error(`Unexpected response '${body}'`)
                                            process.exit(1)
                                        }
                                        try {
                                            body = JSON.parse(body)
                                        } catch (error) {
                                            console.error(error)
                                            process.exit(1)
                                        }
                                        fs.writeFileSync(`${answers['emailAddress']}.cert.pem`, body['cert'], { mode: 0o444 })
                                    } else {
                                        console.error(`Unexpected status code '${response.statusCode}'`)
                                        process.exit(1)
                                    }
                                })
                            })
                            request.on('error', error => {
                                console.error(error)
                                process.exit(1)
                            })
                            request.write(payload)
                            request.end()
                        }).catch(error => {
                            console.error(error)
                            process.exit(1)
                        })
                } else {
                    console.error(`Unexpected status code '${response.statusCode}'`)
                    process.exit(1)
                }
            })
        })
        request.on('error', error => {
            console.error(error)
            process.exit(1)
        })
        request.write(payload)
        request.end()
    }).catch(error => {
        console.error(error)
        process.exit(1)
    })
