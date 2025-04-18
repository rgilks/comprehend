export type Language =
  | 'en'
  | 'es'
  | 'fr'
  | 'de'
  | 'it'
  | 'pt'
  | 'ru'
  | 'zh'
  | 'ja'
  | 'ko'
  | 'hi'
  | 'he'
  | 'fil'
  | 'la'
  | 'el'
  | 'pl';

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
  hi: 'हिंदी',
  he: 'עברית',
  fil: 'Filipino',
  la: 'Latin',
  el: 'Ελληνικά',
  pl: 'Polski',
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
  hi: 'hi-IN',
  he: 'he-IL',
  fil: 'fil-PH',
  la: 'la-VA',
  el: 'el-GR',
  pl: 'pl-PL',
};

// Define languages available for learning content
export type LearningLanguage = Exclude<Language, 'zh' | 'ja' | 'ko'>;

export const LEARNING_LANGUAGES: Record<LearningLanguage, string> = {
  en: 'English',
  es: 'Español',
  fr: 'Français',
  de: 'Deutsch',
  it: 'Italiano',
  pt: 'Português',
  ru: 'Русский',
  // zh: '中文',
  // ja: '日本語',
  // ko: '한국어',
  hi: 'हिंदी',
  he: 'עברית',
  fil: 'Filipino',
  la: 'Latin',
  el: 'Ελληνικά',
  pl: 'Polski',
};

export const RTL_LANGUAGES: Language[] = ['he'];

export const getTextDirection = (language: Language): 'ltr' | 'rtl' => {
  return RTL_LANGUAGES.includes(language) ? 'rtl' : 'ltr';
};
