import { getToken } from "@stores/tokens";

const hostname = window.location.hostname;
console.log(hostname);

async function checkForPasswordInputs(): Promise<boolean> {
    const form = (document.querySelector(
        'form input[type="password"]',
    ) as HTMLInputElement)?.form;

    if (form) {
        const accessToken = await getToken("accessToken");
        if (!accessToken) {
            console.log("accessToken not present during check.")
            return false;
        }
        const password = await getPassword(hostname, accessToken as string);

        const usernameInput = form.querySelector('input[type="email"]') || form.querySelector('input[type="text"]');
        const passwordInput = form.querySelector('input[type="password"]');

        [usernameInput, passwordInput].forEach(element => {
            (element as Element).addEventListener('input', () => {
                const input = element as HTMLInputElement;
                if (!input.value) {
                    input.focus();
                    input.value = input.type === 'password' ? password : 'jefnic23@gmail.com';
                }
            });
        });
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

// Run the initial check and start observing
(async () => {
    await checkForPasswordInputs();
    await startMutationObserver();
})();

async function getPassword(hostname: string, accessToken: string): Promise<string> {
    const response = await fetch(`http://127.0.0.1:8000/services/${hostname}`, {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });

    if (response.status == 200) {
        const password: string = await response.json();
        return password;
    } else if (response.status == 401) {
        console.log("Unable to validate credentials.");
    } else {
        console.log("Error retrieving password.");
    }

    return "";
}
