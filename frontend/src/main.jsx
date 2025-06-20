import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import {BrowserRouter, RouterProvider} from 'react-router-dom'
export const serverUrl="https://chatlyfy-backend.onrender.com"
import {Provider} from "react-redux"
import { store } from './redux/store.js'

createRoot(document.getElementById('root')).render(
   <BrowserRouter>
   <Provider store={store}>
      <App/>
   </Provider>
   </BrowserRouter>
)
