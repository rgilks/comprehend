'use client';

import { signIn, signOut, useSession } from 'next-auth/react';
import Image from 'next/image';
import Link from 'next/link';
import { Session } from 'next-auth';
import { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';

interface AuthButtonProps {
  variant?: 'full' | 'icon-only' | 'short';
}

type AuthUser = {
  name?: string | null;
  email?: string | null;
  image?: string | null;
  isAdmin?: boolean;
};

type AuthSession = Session & { user: AuthUser };

const ProviderButton = ({
  provider,
  variant,
  onClick,
  title,
  children,
  className,
}: {
  provider: string;
  variant: 'full' | 'icon-only' | 'short';
  onClick: () => void;
  title: string;
  children: React.ReactNode;
  className: string;
}) => (
  <button
    onClick={() => {
      onClick();
    }}
    className={className}
    title={title}
    type="button"
  >
    {children}
    {variant === 'full' && <span>{title}</span>}
    {variant === 'short' && <span>{provider.charAt(0).toUpperCase() + provider.slice(1)}</span>}
  </button>
);

const UserMenu = ({
  user,
  show,
  setShow,
  t,
}: {
  user: AuthUser;
  show: boolean;
  setShow: (show: boolean) => void;
  t: (key: string) => string;
}) => (
  <div
    className={`absolute right-0 top-full mt-2 w-48 rounded-md shadow-lg z-10 transition-all duration-200 ease-out origin-top-right ${show ? 'opacity-100 scale-100' : 'opacity-0 scale-95 pointer-events-none'}`}
    aria-hidden={!show}
    role="menu"
  >
    <div className="bg-gray-800 rounded-md shadow-xl border border-gray-700 overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-700">
        <p className="text-sm text-white">{user.name}</p>
        <p className="text-xs text-gray-400 truncate">{user.email}</p>
      </div>
      <div className="py-1">
        {user.isAdmin && (
          <Link
            href="/admin"
            className="block px-4 py-2 text-sm text-white hover:bg-gray-700 transition-colors w-full text-left focus:outline-none focus-visible:bg-gray-700 focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-blue-600"
            onClick={() => {
              setShow(false);
            }}
          >
            {t('navigation.admin')}
          </Link>
        )}
        <button
          onClick={() => {
            void signOut();
            setShow(false);
          }}
          data-testid="sign-out-button"
          className="block px-4 py-2 text-sm text-white hover:bg-gray-700 transition-colors w-full text-left focus:outline-none focus-visible:bg-gray-700 focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-blue-600"
          type="button"
        >
          {t('auth.signOut')}
        </button>
      </div>
    </div>
  </div>
);

const AuthButton = ({ variant = 'full' }: AuthButtonProps) => {
  const { data: session, status } = useSession() as {
    data: AuthSession | null;
    status: 'loading' | 'authenticated' | 'unauthenticated';
  };
  const [isMounted, setIsMounted] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const { t } = useTranslation();

  useEffect(() => {
    setIsMounted(true);
  }, []);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setShowUserMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  if (!isMounted || status === 'loading') {
    return <div className="animate-pulse bg-gray-700 h-10 w-32 rounded-lg" role="status" />;
  }

  if (session) {
    return (
      <div className="flex flex-wrap items-center gap-2 md:gap-4 relative" ref={userMenuRef}>
        <button
          className="flex items-center gap-2 hover:opacity-80 transition-opacity focus:outline-none focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-900 focus-visible:ring-blue-500 rounded-full p-1"
          onClick={() => {
            setShowUserMenu(!showUserMenu);
          }}
          type="button"
        >
          <div className="flex items-center gap-2">
            {session.user.image && (
              <Image
                src={session.user.image}
                alt={session.user.name || 'User'}
                width={32}
                height={32}
                className="rounded-full animate-scale-up"
              />
            )}
            {variant === 'full' && <span className="text-white">{session.user.name}</span>}
          </div>
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            className={`transition-transform duration-300 ${showUserMenu ? 'rotate-180' : ''}`}
          >
            <path d="M6 9l6 6 6-6" />
          </svg>
        </button>
        <UserMenu user={session.user} show={showUserMenu} setShow={setShowUserMenu} t={t} />
      </div>
    );
  }

  return (
    <div className="flex gap-3 flex-row">
      <ProviderButton
        provider="google"
        variant={variant}
        onClick={() => void signIn('google')}
        title={t('auth.signInGoogle')}
        className={`flex items-center justify-center transition-all duration-300 hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-900 focus-visible:ring-blue-500 ${variant === 'icon-only' ? 'p-2 bg-gray-700 text-white rounded-full hover:bg-gray-600' : 'px-4 py-2 bg-white text-gray-800 rounded-lg hover:bg-gray-100 gap-2 hover:translate-y-[-2px]'}`}
      >
        <svg className="w-5 h-5" viewBox="0 0 24 24">
          <path
            fill="#4285F4"
            d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
          />
          <path
            fill="#34A853"
            d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
          />
          <path
            fill="#FBBC05"
            d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
          />
          <path
            fill="#EA4335"
            d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
          />
          <path fill="none" d="M1 1h22v22H1z" />
        </svg>
      </ProviderButton>
      <ProviderButton
        provider="github"
        variant={variant}
        onClick={() => void signIn('github')}
        title={t('auth.signInGitHub')}
        className={`flex items-center justify-center transition-all duration-300 hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-900 focus-visible:ring-gray-500 ${variant === 'icon-only' ? 'p-2 bg-gray-700 text-white rounded-full hover:bg-gray-600' : 'px-4 py-2 bg-gray-800 text-white rounded-lg hover:bg-gray-700 gap-2 hover:translate-y-[-2px]'}`}
      >
        <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
          <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
        </svg>
      </ProviderButton>
      <ProviderButton
        provider="discord"
        variant={variant}
        onClick={() => void signIn('discord')}
        title={t('auth.signInDiscord')}
        className={`flex items-center justify-center transition-all duration-300 hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-900 focus-visible:ring-[#5865F2] ${variant === 'icon-only' ? 'p-2 bg-[#5865F2] text-white rounded-full hover:bg-[#4f5bda]' : 'px-4 py-2 bg-[#5865F2] text-white rounded-lg hover:bg-[#4f5bda] gap-2 hover:translate-y-[-2px]'}`}
      >
        <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
          <path d="M20.317 4.369a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.078.037c-.21.375-.444.864-.608 1.229a18.29 18.29 0 00-5.484 0 10.02 10.02 0 00-.617-1.229.076.076 0 00-.078-.037 19.736 19.736 0 00-4.885 1.515.069.069 0 00-.032.056c-.008.115-.018.255-.026.415a19.081 19.081 0 005.022 15.18.076.076 0 00.087.015 19.9 19.9 0 003.757-1.386 18.18 18.18 0 002.948 1.386.074.074 0 00.087-.015 19.078 19.078 0 005.022-15.18c-.01-.16-.02-.3-.028-.415a.07.07 0 00-.032-.056zM8.03 15.912c-1.104 0-2-.896-2-2s.896-2 2-2 2 .896 2 2-.896 2-2 2zm7.94 0c-1.104 0-2-.896-2-2s.896-2 2-2 2 .896 2 2-.896 2-2 2z" />
        </svg>
      </ProviderButton>
    </div>
  );
};

export default AuthButton;
