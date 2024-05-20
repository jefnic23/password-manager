import { type Token, isExpired } from "./interfaces/token";
import browser from "webextension-polyfill";

const hostname = window.location.hostname;
console.log(hostname);

// Run the initial check and start observing
(async () => {
    await checkForPasswordInputs();
    await startMutationObserver();
})();

async function checkForPasswordInputs(): Promise<boolean> {
    const form = (document.querySelector(
        'form input[type="password"]',
    ) as HTMLInputElement)?.form;

    if (form) {
        let accessToken = await getToken("accessToken");

        if (!accessToken) {
            console.log("accessToken not present during check.")
            return false;
        }

        if (isExpired(accessToken)) {
            const refreshToken = await getToken("refreshToken");

            if (!refreshToken) {
                console.log("refreshToken not present during check.");
                return false;
            }

            const response = await fetch(`http://127.0.0.1:8000/refresh`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ refreshToken: refreshToken }),
            });

            if (response.status !== 200) {
                console.log("Error refreshing access.");
                return false;
            }

            const responseData: Token = await response.json();
            await saveToken({ accessToken: responseData.accessToken });
            await saveToken({ refreshToken: responseData.refreshToken });

            accessToken = responseData.accessToken;
        }

        let password = await getPassword(hostname, accessToken as string);

        if (!password) {
            return false;
            // password = await createPassword(hostname, accessToken);
        }

        const usernameInput = form.querySelector('input[type="email"]') || form.querySelector('input[type="text"]');
        if (usernameInput){
            setInputValue(usernameInput as HTMLInputElement, "jefnic23@gmail.com");
        }

        const passwordInput = form.querySelector('input[type="password"]');
        if (passwordInput) {
            setInputValue(passwordInput as HTMLInputElement, password);
        }
    }

    return form != null;
}

async function startMutationObserver(): Promise<void> {
    const observer = new MutationObserver(async mutations => {
        for (const mutation of mutations) {
            if (mutation.addedNodes.length > 0) {
                const found = await checkForPasswordInputs();
                if (found) {
                    observer.disconnect();  // Stop observing if password input is found
                    console.log("Observer disconnected: Password input found.");
                    break;
                }
            }
        }
    });

    // Start observing the body for added nodes
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });

    // Remember to disconnect the observer when it's no longer needed to avoid memory leaks
    window.addEventListener('unload', () => observer.disconnect());
}

function setInputValue(field: HTMLInputElement, value: string) {
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    if (nativeInputValueSetter) {
        nativeInputValueSetter.call(field, value);

        field.dispatchEvent(new Event('focus', { bubbles: true }))
        field.dispatchEvent(new Event('input', { bubbles: true }));
        field.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
        console.error('Failed to get property descriptor for value setter.');
    }
}

async function getToken(token: string): Promise<string | null> {
    const result = await browser.storage.local.get(token);
    if (result[token]) {
        console.log(`${token} retrieved from storage.`);
        return result[token];
    } else {
        console.log(`${token} not found.`);
        return null;
    }
}

async function saveToken(token: Record<string, string>): Promise<void> {
    try {
        await browser.storage.local.set(token);
    } catch {
        console.log(`Error saving token.`);
    } finally {
        console.log(`token saved.`);
    }
}

async function getPassword(hostname: string, accessToken: string): Promise<string> {
    const response = await fetch(`http://127.0.0.1:8000/services/${hostname}`, {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });

    if (response.status === 200) {
        const password: string = await response.json();
        return password;
    } else if (response.status === 401) {
        console.log("Unable to validate credentials.");
    } else if (response.status === 404) {
        console.log("Password not found.");
    } else {
        console.log("Error retrieving password.");
    }

    return "";
}

async function createPassword(hostname: string, accessToken: string): Promise<string> {
    const response = await fetch(`http://127.0.0.1:8000/services/${hostname}`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ name: hostname })
    });

    if (response.status === 200) {
        const password: string = await response.json();
        return password;
    } else if (response.status === 401) {
        console.log("Unable to validate credentials.");
    } else {
        console.log("Error creating password.");
    }

    return "";
}
