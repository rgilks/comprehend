'use client';

import React, { createContext, useContext, useState, ReactNode } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import i18n from '../i18n.client';

export type Language = 'en' | 'es' | 'fr' | 'de' | 'it' | 'pt' | 'ru' | 'zh' | 'ja' | 'ko';

export const LANGUAGES: Record<Language, string> = {
  en: 'English',
  es: 'Español',
  fr: 'Français',
  de: 'Deutsch',
  it: 'Italiano',
  pt: 'Português',
  ru: 'Русский',
  zh: '中文',
  ja: '日本語',
  ko: '한국어',
};

export const SPEECH_LANGUAGES: Record<Language, string> = {
  en: 'en-US',
  es: 'es-ES',
  fr: 'fr-FR',
  de: 'de-DE',
  it: 'it-IT',
  pt: 'pt-PT',
  ru: 'ru-RU',
  zh: 'zh-CN',
  ja: 'ja-JP',
  ko: 'ko-KR',
};

export const RTL_LANGUAGES: Language[] = [];

interface LanguageContextType {
  language: Language;
  setLanguage: (lang: Language) => Promise<void>;
  languages: typeof LANGUAGES;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

export function LanguageProvider({
  children,
  initialLanguage,
}: {
  children: ReactNode;
  initialLanguage: Language;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const [language, setLanguage] = useState<Language>(initialLanguage);

  const handleLanguageChange = async (lang: Language) => {
    setLanguage(lang);
    await i18n.changeLanguage(lang);

    // Update the URL with the new language
    const segments = pathname.split('/');
    segments[1] = lang;
    router.push(segments.join('/'));
  };

  return (
    <LanguageContext.Provider
      value={{ language, setLanguage: handleLanguageChange, languages: LANGUAGES }}
    >
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (context === undefined) {
    throw new Error('useLanguage must be used within a LanguageProvider');
  }
  return context;
}

export function getTextDirection(language: Language) {
  return RTL_LANGUAGES.includes(language) ? 'rtl' : 'ltr';
}
