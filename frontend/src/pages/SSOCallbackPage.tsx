import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';

/**
 * SSO Callback Page
 *
 * Página chamada após o retorno do provider SSO (Microsoft Entra ID, Google, etc)
 * Recebe o JWT token via query string e atualiza o authStore
 */
const SSOCallbackPage = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = searchParams.get('token');
    const errorParam = searchParams.get('error');

    if (errorParam) {
      // Tratar erros do SSO
      let errorMessage = 'Erro na autenticação SSO';

      switch (errorParam) {
        case 'provider_not_found':
          errorMessage = 'Provedor SSO não encontrado ou inativo';
          break;
        case 'user_inactive':
          errorMessage = 'Sua conta está desativada';
          break;
        case 'account_disabled':
          errorMessage = 'Sua conta foi desativada no sistema corporativo';
          break;
        case 'account_not_found':
          errorMessage = 'Conta não encontrada no Microsoft Entra ID';
          break;
        case 'auto_provision_disabled':
          errorMessage = 'Auto-provisionamento está desativado. Contate o administrador';
          break;
        case 'sso_error':
          errorMessage = 'Erro durante a autenticação SSO';
          break;
      }

      setError(errorMessage);

      // Redirecionar para login após 3 segundos
      setTimeout(() => {
        navigate('/login', { state: { error: errorMessage } });
      }, 3000);

      return;
    }

    if (token) {
      try {
        // Decodificar token para pegar informações do usuário
        const payload = JSON.parse(atob(token.split('.')[1]));
        console.log('✅ SSO Login successful:', payload);

        // Atualizar authStore diretamente via setState (método interno do Zustand persist)
        useAuthStore.setState({
          token: token,
          isAuthenticated: true,
        });

        // Carregar dados completos do usuário usando getState()
        const { loadUser } = useAuthStore.getState();
        loadUser().then(() => {
          // Redirecionar para dashboard após carregar usuário
          console.log('✅ User loaded, redirecting to dashboard...');
          navigate('/');
        }).catch((err) => {
          console.error('❌ Error loading user:', err);
          setError('Erro ao carregar dados do usuário');
          setTimeout(() => {
            navigate('/login');
          }, 2000);
        });
      } catch (err) {
        console.error('❌ Error processing SSO token:', err);
        setError('Token inválido');
        setTimeout(() => {
          navigate('/login');
        }, 2000);
      }
    } else {
      // Sem token e sem erro - algo deu errado
      setError('Resposta inválida do servidor SSO');
      setTimeout(() => {
        navigate('/login');
      }, 2000);
    }
  }, [searchParams, navigate]);

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <div className="max-w-md w-full bg-white shadow-lg rounded-lg p-8">
          <div className="flex flex-col items-center">
            <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mb-4">
              <svg className="w-8 h-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </div>
            <h2 className="text-xl font-semibold text-gray-900 mb-2">Erro na Autenticação</h2>
            <p className="text-gray-600 text-center mb-4">{error}</p>
            <p className="text-sm text-gray-500">Redirecionando para login...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-50">
      <div className="max-w-md w-full bg-white shadow-lg rounded-lg p-8">
        <div className="flex flex-col items-center">
          <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4 animate-pulse">
            <svg className="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Processando login...</h2>
          <p className="text-gray-600 text-center">Autenticando com SSO</p>
          <div className="mt-4">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SSOCallbackPage;
