import React from 'react';
import Login from 'pages/Login';
import Home from 'pages/Home';
import { Routes, Route } from 'react-router-dom';
import ProtectedRoute from 'components/ProtectedRoute';

export default function App() {
	return (
		<Routes>
			<Route 
				index 
				element={
					<ProtectedRoute>
						<Home />
					</ProtectedRoute>
				} 
			/>
			<Route path="/login" element={<Login />} />
		</Routes>
	);
}
