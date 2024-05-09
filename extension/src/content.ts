// import { getAccessToken } from "./stores";

const hostname = window.location.hostname;

console.log(hostname);

function checkForPasswordInputs(): boolean {
    const inputs = document.querySelectorAll(
        'input[type="Password"]',
    );
    
    return inputs.length > 0;
}

const observer = new MutationObserver(mutations => {
    for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
            const found = checkForPasswordInputs();
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

