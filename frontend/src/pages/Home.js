import React, { useContext, useEffect, useState } from 'react';
import { Context } from 'globalState/Store';
import Container from 'components/Container';

export default function Home() {
    const [state, dispatch] = useContext(Context);
    const [services, setServices] = useState([]);

    useEffect(() => {
        if (state.authenticated) {
            let requestOptions = {
                method: "GET",
                headers: {'Authorization': `Bearer ${state.token}`}
            };

            fetch(`/api/services`, requestOptions)
                .then(res => res.json())
                .then(data => setServices(data.services))
                .catch(err => console.log(err));
        }
    }, [state.authenticated, state.token]);

    return (
        <Container>
            <select>
                <option></option>
                {services && services.map((service) => <option key={service} value={service}>{service}</option>)}
            </select>
        </Container>
    );
}
