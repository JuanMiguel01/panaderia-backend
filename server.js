// src/App.jsx
import React, { useState, useEffect, useCallback } from 'react';
import { io } from 'socket.io-client';
import { api } from './services/api';
import { Auth } from './components/Auth';
import { Dashboard } from './components/Dashboard/Dashboard';

// ✅ CORREGIDO: Usar variable de entorno
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3001';

function App() {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [batches, setBatches] = useState([]);
  const [socket, setSocket] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  // handleLogout SIN dependencias para evitar recreación
  const handleLogout = useCallback(() => {
    setSocket(currentSocket => {
      if (currentSocket) {
        currentSocket.disconnect();
      }
      return null;
    });
    
    localStorage.removeItem('jwt_token');
    localStorage.removeItem('user_info');
    setToken(null);
    setUser(null);
    setBatches([]);
    setError(null);
  }, []);

  const handleLogin = async (email, password) => {
    const data = await api.login(email, password);
    localStorage.setItem('jwt_token', data.token);
    localStorage.setItem('user_info', JSON.stringify(data.user));
    setToken(data.token);
    setUser(data.user);
    setError(null);
  };

  const handleRegister = (email, password) => api.register(email, password);

  const fetchBatches = useCallback(async () => {
    try {
      const fetchedBatches = await api.getBatches(handleLogout);
      setBatches(fetchedBatches);
    } catch (err) {
      setError("Error al cargar los lotes.");
    }
  }, [handleLogout]);

  // Verificar token guardado al montar el componente
  useEffect(() => {
    const savedToken = localStorage.getItem('jwt_token');
    const savedUser = localStorage.getItem('user_info');
    if (savedToken && savedUser) {
      setToken(savedToken);
      setUser(JSON.parse(savedUser));
    }
    setIsLoading(false);
  }, []);

  // Configurar socket y cargar datos cuando el usuario esté logueado
  useEffect(() => {
    if (!user || !token) return;

    fetchBatches();

    // ✅ MEJORADO: Configuración de socket más robusta
    const newSocket = io(API_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      timeout: 10000,
      forceNew: true // Forzar nueva conexión
    });

    setSocket(newSocket);

    // Manejar eventos del socket
    newSocket.on('connect', () => {
      console.log('📡 Conectado al servidor Socket.IO!');
      console.log('🔗 Socket ID:', newSocket.id);
      console.log('🌍 Conectado a:', API_URL);
    });

    newSocket.on('disconnect', (reason) => {
      console.log('📡 Desconectado del servidor Socket.IO:', reason);
    });

    newSocket.on('connect_error', (error) => {
      console.error('❌ Error de conexión Socket.IO:', error);
      console.error('🔗 Intentando conectar a:', API_URL);
    });

    // ✅ MEJORADO: Manejo de eventos más específico
    const handleBatchEvents = async (eventData) => {
      console.log('🔄 Evento recibido, recargando datos...', eventData);
      try {
        const fetchedBatches = await api.getBatches(handleLogout);
        setBatches(fetchedBatches);
      } catch (err) {
        setError("Error al cargar los lotes.");
      }
    };

    newSocket.on('batch:created', handleBatchEvents);
    newSocket.on('batch:deleted', handleBatchEvents);
    newSocket.on('sale:created', handleBatchEvents);
    newSocket.on('sale:updated', handleBatchEvents);
    newSocket.on('sale:deleted', handleBatchEvents);

    if (user?.role === 'admin') {
      newSocket.on('user:registered', (userData) => {
        console.log('📧 Nuevo usuario registrado:', userData.email);
      });

      newSocket.on('user:approved', (userData) => {
        console.log('✅ Usuario aprobado:', userData.email);
      });
    }

    // Cleanup cuando el componente se desmonte o cambie el usuario
    return () => {
      console.log('🧹 Limpiando conexión Socket.IO...');
      newSocket.off('connect');
      newSocket.off('disconnect');
      newSocket.off('connect_error');
      newSocket.off('batch:created');
      newSocket.off('batch:deleted');
      newSocket.off('sale:created');
      newSocket.off('sale:updated');
      newSocket.off('sale:deleted');
      newSocket.off('user:registered');
      newSocket.off('user:approved');
      newSocket.disconnect();
    };
  }, [user, token, fetchBatches]);

  const handleCreateBatch = useCallback(async (batchData) => {
    console.log('App.jsx - handleCreateBatch llamado con:', batchData);
    try {
      await api.createBatch(batchData, handleLogout);
    } catch (err) {
      console.error('App.jsx - Error en handleCreateBatch:', err);
      setError(err.message || "Error al crear lote.");
    }
  }, [handleLogout]);

  const handleDeleteBatch = useCallback(async (...args) => {
    try {
      await api.deleteBatch(...args, handleLogout);
    } catch (err) {
      setError(err.message || "Error al eliminar lote.");
    }
  }, [handleLogout]);

  const handleCreateSale = useCallback(async (...args) => {
    try {
      await api.createSale(...args, handleLogout);
    } catch (err) {
      setError(err.message || "Error al crear venta.");
    }
  }, [handleLogout]);

  const handleUpdateSale = useCallback(async (...args) => {
    try {
      await api.updateSale(...args, handleLogout);
    } catch (err) {
      setError(err.message || "Error al actualizar venta.");
    }
  }, [handleLogout]);

  const handleDeleteSale = useCallback(async (...args) => {
    try {
      await api.deleteSale(...args, handleLogout);
    } catch (err) {
      setError(err.message || "Error al eliminar venta.");
    }
  }, [handleLogout]);

  if (isLoading) {
    return (
      <div className="fixed inset-0 flex items-center justify-center bg-gradient-to-br from-amber-50 to-orange-100">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-orange-200 border-t-orange-500 rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-orange-700 font-medium">Cargando panadería...</p>
        </div>
      </div>
    );
  }

  return (
    <>
      {error && (
        <div className="fixed top-5 right-5 bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-xl shadow-lg z-50 max-w-md" role="alert">
          <div className="flex items-start">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3 flex-1">
              <h3 className="text-sm font-medium text-red-800">¡Error!</h3>
              <p className="mt-1 text-sm text-red-700">{error}</p>
            </div>
            <button 
              className="ml-3 flex-shrink-0 text-red-400 hover:text-red-600 transition-colors"
              onClick={() => setError(null)}
            >
              <svg className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
            </button>
          </div>
        </div>
      )}

      {!user ? (
        <Auth onLogin={handleLogin} onRegister={handleRegister} />
      ) : (
        <Dashboard
          user={user}
          batches={batches}
          onLogout={handleLogout}
          handleCreateBatch={handleCreateBatch}
          handleDeleteBatch={handleDeleteBatch}
          handleCreateSale={handleCreateSale}
          handleUpdateSale={handleUpdateSale}
          handleDeleteSale={handleDeleteSale}
        />
      )}
    </>
  );
}

export default App;