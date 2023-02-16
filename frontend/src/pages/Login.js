import React, { useState } from 'react';
import Button from 'components/Button';
import Checkbox from 'components/Checkbox';
import Container from 'components/Container';
import Form from 'components/Form';
import FormItem from 'components/FormItem';
import Icon from 'components/Icon';
import TextInput from 'components/TextInput';
import { faUser, faLock } from '@fortawesome/free-solid-svg-icons';

export default function Login() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [rememberMe, setRememberMe] = useState(false);

    const iconSize = 'sm';

    /**
     * Processes the submitted login form.
     * 
     * @param {*} e 
     */
    const handleSubmit = (e) => {
        e.preventDefault();

        let requestOptions = {
            method: "POST",
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ email: email, password: password })
        };

        fetch(`/api/login`, requestOptions)
            .then(res => res.json())
            .then(data => console.log(data))
            .catch(err => console.log(err));
    }

    /**
     * Toggle remember me status.
     * 
     */
    const handleChange = () => {
        setRememberMe(!rememberMe);
    }

    return (
        <Container>
            <h2>Login</h2>
            <Form handleSubmit={handleSubmit}>
                <FormItem>
                    <Icon 
                        icon={faUser}
                        size={iconSize}
                    />
                    <TextInput
                        placeholder='Email'
                        type='email'
                        value={email}
                        onChange={setEmail}
                        icon={faUser}
                        autoFocus
                        required
                    />
                </FormItem>
                <FormItem>
                    <Icon 
                        icon={faLock}
                        size={iconSize}
                    />
                    <TextInput
                        placeholder='Password'
                        type='password'
                        value={password}
                        onChange={setPassword}
                        icon={faLock}
                        required
                    />
                </FormItem>
                <Checkbox
                    checked={rememberMe}
                    onChange={handleChange}
                    label='Remember me'
                />
                <Button type='submit'>Submit</Button>
            </Form>
            <button>Forgot your password?</button>
            <button>Create an account.</button>
        </Container>
    )
}
