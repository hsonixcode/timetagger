const puppeteer = require('puppeteer'); // v23.0.0 or later

(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    const timeout = 5000;
    page.setDefaultTimeout(timeout);

    {
        const targetPage = page;
        await targetPage.setViewport({
            width: 1173,
            height: 880
        })
    }
    {
        const targetPage = page;
        await targetPage.goto('http://localhost:8000/timetagger/login');
    }
    {
        const targetPage = page;
        const promises = [];
        const startWaitingForEvents = () => {
            promises.push(targetPage.waitForNavigation());
        }
        await puppeteer.Locator.race([
            targetPage.locator('::-p-aria(Login with Azure AD)'),
            targetPage.locator('div.login-container > button'),
            targetPage.locator('::-p-xpath(//*[@id=\\"main-content\\"]/div[2]/button)'),
            targetPage.locator(':scope >>> div.login-container > button'),
            targetPage.locator('::-p-text(Login with Azure)')
        ])
            .setTimeout(timeout)
            .on('action', () => startWaitingForEvents())
            .click({
              offset: {
                x: 107.34375,
                y: 33.640625,
              },
            });
        await Promise.all(promises);
    }
    {
        const targetPage = page;
        await puppeteer.Locator.race([
            targetPage.locator('::-p-aria(Enter your email, phone, or Skype.)'),
            targetPage.locator('#i0116'),
            targetPage.locator('::-p-xpath(//*[@id=\\"i0116\\"])'),
            targetPage.locator(':scope >>> #i0116')
        ])
            .setTimeout(timeout)
            .fill('hardy@nrgnr.com');
    }
    {
        const targetPage = page;
        await puppeteer.Locator.race([
            targetPage.locator('#i0118'),
            targetPage.locator('::-p-xpath(//*[@id=\\"i0118\\"])'),
            targetPage.locator(':scope >>> #i0118')
        ])
            .setTimeout(timeout)
            .fill('Abcdef12');
    }
    {
        const targetPage = page;
        await puppeteer.Locator.race([
            targetPage.locator('::-p-aria(Next)'),
            targetPage.locator('#idSIButton9'),
            targetPage.locator('::-p-xpath(//*[@id=\\"idSIButton9\\"])'),
            targetPage.locator(':scope >>> #idSIButton9'),
            targetPage.locator('::-p-text(Next)')
        ])
            .setTimeout(timeout)
            .click({
              offset: {
                x: 63.5,
                y: 5.78125,
              },
            });
    }
    {
        const targetPage = page;
        const promises = [];
        const startWaitingForEvents = () => {
            promises.push(targetPage.waitForNavigation());
        }
        await puppeteer.Locator.race([
            targetPage.locator('::-p-aria(Sign in)'),
            targetPage.locator('#idSIButton9'),
            targetPage.locator('::-p-xpath(//*[@id=\\"idSIButton9\\"])'),
            targetPage.locator(':scope >>> #idSIButton9'),
            targetPage.locator('::-p-text(Sign in)')
        ])
            .setTimeout(timeout)
            .on('action', () => startWaitingForEvents())
            .click({
              offset: {
                x: 43.5,
                y: 3.78125,
              },
            });
        await Promise.all(promises);
    }
    {
        const targetPage = page;
        const promises = [];
        const startWaitingForEvents = () => {
            promises.push(targetPage.waitForNavigation());
        }
        await puppeteer.Locator.race([
            targetPage.locator('::-p-aria(Yes)'),
            targetPage.locator('#idSIButton9'),
            targetPage.locator('::-p-xpath(//*[@id=\\"idSIButton9\\"])'),
            targetPage.locator(':scope >>> #idSIButton9'),
            targetPage.locator('::-p-text(Yes)')
        ])
            .setTimeout(timeout)
            .on('action', () => startWaitingForEvents())
            .click({
              offset: {
                x: 31.5,
                y: 25.28125,
              },
            });
        await Promise.all(promises);
    }
    {
        const targetPage = page;
        await puppeteer.Locator.race([
            targetPage.locator('::-p-aria(Show Token Information)'),
            targetPage.locator('div.token-info-container > button'),
            targetPage.locator('::-p-xpath(//*[@id=\\"main-content\\"]/div[2]/div[4]/button)'),
            targetPage.locator(':scope >>> div.token-info-container > button'),
            targetPage.locator('::-p-text(Show Token Information)')
        ])
            .setTimeout(timeout)
            .click({
              offset: {
                x: 134.5,
                y: 16.0625,
              },
            });
    }

    await browser.close();

})().catch(err => {
    console.error(err);
    process.exit(1);
});
