import React, { useContext, useEffect } from 'react';
import { Context } from 'globalState/Store';
import { useNavigate } from 'react-router-dom';

export default function ProtectedRoute(props) {
    const [state, dispatch] = useContext(Context);
    const navigate = useNavigate();

    useEffect(() => {
        // check if user is authenticated
        if (!state.authenticated) {
            // if not authenticated, redirect to dashboard
            return navigate('/login');
        }
    }, [state.authenticated, navigate]);

    return (
        <>
            {props.children}
        </>
    );
}