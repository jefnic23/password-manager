<script lang="ts">
	import Login from "../components/Login.svelte";
	import { accessToken } from "../stores";

	let host: string | undefined;
	let password: string | undefined;
	let loggedIn: boolean = false;

	$: if (loggedIn) {
		chrome.tabs.query(
			{ active: true, currentWindow: true },
			async (tabs) => {
				let activeTab: chrome.tabs.Tab = tabs[0];

				const url: URL = new URL(activeTab.url as string);
				host = url.host;

				console.log(host);

				const response = await fetch(
					`http://127.0.0.1:8000/services/${host}`,
					{
						headers: {
							Authorization: `Bearer ${$accessToken}`,
						},
					},
				);

				const data = await response.json();

				password = data;

				// chrome.scripting.executeScript(
				// 	{
				// 		target: { tabId: activeTab.id as number },
				// 		func: () => {
				// 			const inputs = document.querySelectorAll(
				// 				'input[type="password"]',
				// 			);
				// 			const hasPasswordInput = inputs.length > 0;

				// 			if (hasPasswordInput) {
				// 				const node = inputs[0];

				// 				if (node.ariaHidden) {
				// 					return false;
				// 				}

				// 				const container = document.createElement("div");
				// 				container.style.position = "relative";
				// 				container.style.width = "100%";
				// 				(node.parentNode as HTMLElement).insertBefore(
				// 					container,
				// 					node,
				// 				);
				// 				container.appendChild(node);

				// 				// Create the button
				// 				const button = document.createElement("button");
				// 				button.innerText = "🔑"; // Using an emoji as the button face
				// 				button.style.position = "absolute";
				// 				button.style.right = "0px";
				// 				button.style.top = "50%";
				// 				button.style.border = "none";
				// 				button.style.background = "transparent";
				// 				button.style.transform = "translate(-50%, -50%)";
				// 				button.style.marginRight = "8px";
				// 				button.style.cursor = "pointer";
				// 				button.style.lineHeight = "1";

				// 				if (container.nextElementSibling?.innerHTML) {
				// 					button.style.paddingRight = "25px";
				// 				}

				// 				button.onclick = () => {
				// 					(node as HTMLInputElement).value =
				// 						"YourSecurePassword"; // Set this to generate or fetch a secure password as needed
				// 				};

				// 				// Append the button to the container next to the input
				// 				container.appendChild(button);
				// 			}

				// 			return hasPasswordInput;
				// 		},
				// 	},
				// 	(results) => {
				// 		if (results && results[0]) {
				// 			console.log(
				// 				"Password input fields found:",
				// 				results[0].result,
				// 			);
				// 		} else {
				// 			console.log("No password input fields found.");
				// 		}
				// 	},
				// );
			},
		);
	}
</script>

<div>
	<img src="/icon/128.png" alt="" />
	{#if !loggedIn}
		<Login bind:loggedIn />
	{:else}
		<p>
			Current page: <code>{host}</code>
			Password: <code>{password}</code>
		</p>
	{/if}
</div>

<style>
	img {
		width: 128px;
		height: 128px;
	}
</style>
