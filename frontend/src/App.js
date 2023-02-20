import React from 'react';
import Login from 'pages/Login';
import Store from 'Store';

export default function App() {
  return (
    <Store>
      <Login />
    </Store>
  );
}
