<script lang="ts">
	let host: string | undefined;

	chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
		let activeTab: chrome.tabs.Tab = tabs[0];

		const url: URL = new URL((activeTab.url as string));
		host = url.host;

		chrome.scripting.executeScript(
			{
				target: { tabId: (activeTab.id as number) },
				func: () => {
					const inputs = document.querySelectorAll(
						'input[type="password"]',
					);
					const hasPasswordInput = inputs.length > 0;

					if (hasPasswordInput) {
						(inputs[0] as HTMLInputElement).value = "password";
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
