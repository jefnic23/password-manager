<script lang="ts">
    import { accessToken } from "../stores";
    import { type Token } from "../types/token";

    export let loggedIn: boolean;

    async function handleSubmit(event: Event): Promise<void> {
        const formEl = event.target as HTMLFormElement;
        const data = new FormData(formEl);

        const response = await fetch(formEl.action, {
            method: formEl.method,
            body: data,
        });

        loggedIn = response.status == 200;

        if (loggedIn) {
            const responseData: Token = await response.json();
            accessToken.update(t => t = responseData.access_token);
        }
    }
</script>

<div>
    <form
        method="post"
        action="http://127.0.0.1:8000/login"
        on:submit|preventDefault={handleSubmit}
    >
        <input type="text" name="username" placeholder="email" />
        <input type="password" name="password" placeholder="password" />
        <button type="submit">Submit</button>
    </form>
</div>
