import { SPEECH_LANGUAGES } from 'app/domain/language';
import type { Language } from 'app/domain/language';
import type { VoiceInfo } from 'app/domain/schemas';

export const getPlatformInfo = () => {
  const ua = navigator.userAgent;
  const nav = navigator as Navigator & { userAgentData?: { platform: string } };
  if (typeof nav.userAgentData?.platform === 'string') {
    const platform = nav.userAgentData.platform.toUpperCase();
    return {
      isIOS: platform === 'IOS' || platform === 'IPADOS',
      isMac: platform === 'MACOS',
      isWindows: platform === 'WINDOWS',
      platformString: platform,
    };
  }
  const upperUA = ua.toUpperCase();
  return {
    isIOS: /IPHONE|IPAD|IPOD/.test(upperUA),
    isMac: /MACINTOSH|MAC OS X/.test(upperUA),
    isWindows: /WIN/.test(upperUA),
    platformString: upperUA,
  };
};

export const filterAndFormatVoices = (lang: Language): VoiceInfo[] => {
  if (typeof window === 'undefined') return [];
  const { isIOS, isMac, isWindows } = getPlatformInfo();
  const speechLang = SPEECH_LANGUAGES[lang];
  const baseLangCode = speechLang.split('-')[0];
  let voices = window.speechSynthesis.getVoices();

  if (isIOS) {
    voices = voices.filter((voice) => voice.lang === speechLang);
  } else {
    voices = voices.filter(
      (voice) =>
        baseLangCode && (voice.lang.startsWith(baseLangCode + '-') || voice.lang === baseLangCode)
    );
  }
  voices = voices.filter((voice) => !isMac || !/\s\(.*\s\(.*\)\)$/.test(voice.name));

  const processedVoices = voices.map((voice) => {
    let displayName = voice.name;
    if (isWindows && displayName.startsWith('Microsoft ')) {
      const match = displayName.match(/^Microsoft\s+([^\s]+)\s+-/);
      if (match && match[1]) {
        displayName = match[1];
      }
    } else if (isIOS) {
      const parenIndex = displayName.indexOf(' (');
      if (parenIndex !== -1) {
        displayName = displayName.substring(0, parenIndex);
      }
    }
    return { uri: voice.voiceURI, displayName, originalLang: voice.lang };
  });

  const uniqueVoicesMap = new Map<string, VoiceInfo>();
  for (const voice of processedVoices) {
    if (!uniqueVoicesMap.has(voice.displayName)) {
      uniqueVoicesMap.set(voice.displayName, { uri: voice.uri, displayName: voice.displayName });
    }
  }
  return Array.from(uniqueVoicesMap.values());
};
