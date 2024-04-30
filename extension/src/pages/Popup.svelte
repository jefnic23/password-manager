<script lang="ts">
	let host: string | undefined;

	chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
		let activeTab: chrome.tabs.Tab = tabs[0];

		const url: URL = new URL(activeTab.url as string);
		host = url.host;

		chrome.scripting.executeScript(
			{
				target: { tabId: activeTab.id as number },
				func: () => {
					const inputs = document.querySelectorAll(
						'input[type="password"]',
					);
					const hasPasswordInput = inputs.length > 0;

					if (hasPasswordInput) {
						const node = inputs[0];

						const wrapper = document.createElement("div");
						wrapper.style.position = "relative";
						(node.parentNode as HTMLDivElement).insertBefore(
							wrapper,
							node,
						);
						wrapper.appendChild(node);

						const button = document.createElement("button");
						button.innerText = "🔑";
						button.style.position = "absolute";
						button.style.right = "0px";
						button.style.top = "0px";
						button.style.height = "100%";
						button.style.border = "none";
						button.style.background = "transparent";
						button.style.color = "grey";
						button.style.cursor = "pointer";
						button.onclick = () => {
							(node as HTMLInputElement).value =
								"YourSecurePassword"; // Set this to generate or fetch a secure password as needed
						};

						wrapper.appendChild(button);
					}

					return hasPasswordInput;
				},
			},
			(results) => {
				if (results && results[0]) {
					console.log(
						"Password input fields found:",
						results[0].result,
					);
				} else {
					console.log("No password input fields found.");
				}
			},
		);
	});
</script>

<div>
	<img src="/icon-with-shadow.svg" alt="" />
	<h1>vite-plugin-web-extension</h1>
	<p>
		Current page: <code>{host}</code>
	</p>
</div>

<style>
</style>
