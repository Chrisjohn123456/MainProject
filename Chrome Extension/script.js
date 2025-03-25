document.addEventListener('DOMContentLoaded', function () {
    const result = document.getElementById('result');
    const phishingType = document.getElementById('phishingType');
    const details = document.getElementById('details');
    const redirectMessage = document.getElementById('redirectMessage');

    // List of known safe websites
    const safeWebsites = [
        'google.com',
        'www.google.com',
        'mail.google.com',
        'drive.google.com',
        'docs.google.com',
        'youtube.com',
        'www.youtube.com',
        'microsoft.com',
        'www.microsoft.com',
        'office.com',
        'www.office.com',
        'outlook.com',
        'www.outlook.com',
        'apple.com',
        'www.apple.com',
        'amazon.com',
        'www.amazon.com',
        'facebook.com',
        'www.facebook.com',
        'twitter.com',
        'www.twitter.com',
        'instagram.com',
        'www.instagram.com',
        'linkedin.com',
        'www.linkedin.com',
        'github.com',
        'www.github.com',
        'wikipedia.org',
        'www.wikipedia.org',
        'rajagiritech.ac.in',
        'www.rajagiritech.ac.in',
        'www.amazon.in'
    ];

    // Function to check the URL for phishing
    function checkUrl(url) {
        if (!url) {
            showResult('warning', 'No URL Found', 'No active tab URL was found.');
            return;
        }

        // Extract domain from URL
        let domain;
        try {
            if (url.startsWith('http://') || url.startsWith('https://')) {
                domain = new URL(url).hostname;
            } else {
                domain = new URL('http://' + url).hostname;
            }
        } catch (e) {
            domain = url; // If URL parsing fails, use the input as is
        }

        // Check if the website uses HTTPS
        const usesHttps = url.startsWith('https://');
        const sslMessage = usesHttps
            ? 'This website uses HTTPS and has an SSL certificate.'
            : 'This website does not use HTTPS and may not have an SSL certificate.';

        // Check if it's a known safe website
        if (safeWebsites.includes(domain.toLowerCase())) {
            showResult('safe', 'Safe Website',
                `${domain} is a known legitimate website. Always ensure you're on the official domain and using HTTPS.`);
            return;
        }

        // Check for camera access phishing
        if (checkForCameraPhishing(url)) {
            showResult('danger', 'Camera Access Phishing Detected',
                `This URL appears to contain code that attempts to access your device's camera without clear consent. It may be trying to capture your image while you enter sensitive information. This is a serious privacy and security risk.`);
            return;
        }

        // Check for credential harvesting
        if (checkForCredentialHarvesting(url)) {
            showResult('danger', 'Credential Harvesting Detected',
                `This URL appears to be designed to steal login credentials. It may look like a legitimate login page but will capture and store your username and password.`);
            return;
        }

        // Check for account update phishing
        if (checkForAccountUpdatePhishing(url)) {
            showResult('danger', 'Account Update Phishing Detected',
                `This URL appears to be a fake account update page designed to trick you into providing new credentials that can be used to compromise your accounts.`);
            return;
        }

        // Check for clone phishing
        if (checkForClonePhishing(url)) {
            showResult('danger', 'Clone Phishing Detected',
                `This URL appears to be a clone of a legitimate website, designed to trick you into entering sensitive information.`);
            return;
        }

        // If no specific phishing type is detected but the URL looks suspicious
        if (checkForSuspiciousPatterns(url)) {
            showResult('warning', 'Potentially Suspicious URL',
                `This URL contains some suspicious patterns but doesn't match known phishing types in our database. Exercise caution and verify the legitimacy of the site before entering any information.`);
            return;
        }

        // If nothing suspicious is found
        showResult('safe', 'No Known Phishing Patterns Detected',
            `We didn't detect any known phishing patterns in this URL. However, always remain vigilant and verify the legitimacy of websites before entering sensitive information. ${sslMessage}`);
    }

    // Function to show results
    function showResult(type, title, message) {
        result.className = 'result ' + type;
        phishingType.textContent = title;
        details.textContent = message;
        result.style.display = 'block';
    }

    // Function to check for camera access phishing
    function checkForCameraPhishing(url) {
        const cameraPhishingPatterns = [
            'getUserMedia',
            'camera access',
            'hiddenVideo',
            'captureAndSaveImage',
            'mediaDevices.getUserMedia'
        ];
        return cameraPhishingPatterns.some(pattern => url.toLowerCase().includes(pattern));
    }

    // Function to check for credential harvesting
    function checkForCredentialHarvesting(url) {
        const credentialHarvestingPatterns = [
            'login',
            'signin',
            'account',
            'password',
            'username',
            'credential'
        ];
        const matchCount = credentialHarvestingPatterns.filter(pattern =>
            url.toLowerCase().includes(pattern)).length;
        return matchCount >= 2;
    }

    // Function to check for account update phishing
    function checkForAccountUpdatePhishing(url) {
        const accountUpdatePatterns = [
            'update',
            'verify',
            'confirm',
            'secure',
            'newPassword',
            'newUsername'
        ];
        const matchCount = accountUpdatePatterns.filter(pattern =>
            url.toLowerCase().includes(pattern)).length;
        return matchCount >= 2;
    }

    // Function to check for clone phishing
    function checkForClonePhishing(url) {
        const clonePhishingPatterns = [
            'secure',
            'login',
            'account',
            'update',
            'verify',
            'bank',
            'paypal',
            'ebay',
            'amazon',
            'microsoft',
            'apple',
            'google',
            'facebook'
        ];
        for (const pattern of clonePhishingPatterns) {
            if (url.toLowerCase().includes(pattern)) {
                const legitimateDomain = pattern + '.com';
                if (!url.toLowerCase().includes(legitimateDomain)) {
                    return true;
                }
            }
        }
        return false;
    }

    // Function to check for suspicious patterns
    function checkForSuspiciousPatterns(url) {
        const suspiciousPatterns = [
            'secure',
            'login',
            'account',
            'update',
            'verify',
            'bank',
            'paypal',
            'ebay',
            'amazon',
            'microsoft',
            'apple',
            'google',
            'facebook'
        ];
        for (const pattern of suspiciousPatterns) {
            if (url.toLowerCase().includes(pattern)) {
                const legitimateDomain = pattern + '.com';
                if (!url.toLowerCase().includes(legitimateDomain)) {
                    return true;
                }
            }
        }
        return (
            url.includes('@') ||
            url.includes('bit.ly/') ||
            url.includes('goo.gl/') ||
            url.includes('tinyurl.com/') ||
            /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url) || // IP address
            url.split('.').length > 3 // Too many subdomains
        );
    }

    // Get the current tab's URL and check it
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        const currentTab = tabs[0];
        if (currentTab && currentTab.url) {
            checkUrl(currentTab.url);
        } else {
            showResult('warning', 'No URL Found', 'No active tab URL was found.');
        }
    });
});