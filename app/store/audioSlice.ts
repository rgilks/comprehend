import type { StateCreator } from 'zustand';
import { type Language, SPEECH_LANGUAGES } from 'app/domain/language';
import type { TextGeneratorState } from './textGeneratorStore';
import { translateWordWithGoogle } from 'app/actions/translate';
import type { VoiceInfo } from 'app/domain/schemas';
import { filterAndFormatVoices } from 'app/utils/speech';

export interface AudioSlice {
  isSpeechSupported: boolean;
  isSpeakingPassage: boolean;
  isPaused: boolean;
  volume: number;
  currentWordIndex: number | null;
  passageUtteranceRef: SpeechSynthesisUtterance | null;
  wordsRef: string[];
  availableVoices: VoiceInfo[];
  selectedVoiceURI: string | null;
  translationCache: Map<string, string>;

  setVolumeLevel: (volume: number) => void;
  stopPassageSpeech: () => void;
  handlePlayPause: () => void;
  handleStop: () => void;
  getTranslation: (word: string, sourceLang: string, targetLang: string) => Promise<string | null>;
  speakText: (text: string | null, lang: Language) => void;
  setIsSpeechSupported: (supported: boolean) => void;
  updateAvailableVoices: (lang: Language) => void;
  setSelectedVoiceURI: (uri: string | null) => void;
}

export const createAudioSlice: StateCreator<
  TextGeneratorState,
  [['zustand/immer', never]],
  [],
  AudioSlice
> = (set, get) => ({
  isSpeechSupported: false,
  isSpeakingPassage: false,
  isPaused: false,
  volume: 0.5,
  currentWordIndex: null,
  passageUtteranceRef: null,
  wordsRef: [],
  availableVoices: [],
  selectedVoiceURI: null,
  translationCache: new Map<string, string>(),

  setIsSpeechSupported: (supported) => {
    set((state) => {
      state.isSpeechSupported = supported;
      if (supported && typeof window !== 'undefined') {
        window.speechSynthesis.onvoiceschanged = () => {
          get().updateAvailableVoices(get().passageLanguage);
        };
        get().updateAvailableVoices(get().passageLanguage);
      }
    });
  },

  setVolumeLevel: (volume) => {
    set((state) => {
      state.volume = volume;
    });
    const { passageUtteranceRef } = get();

    if (passageUtteranceRef) {
      passageUtteranceRef.volume = volume;
    }

    if (window.speechSynthesis.speaking && !get().isPaused) {
      window.speechSynthesis.cancel();
      if (passageUtteranceRef) {
        window.speechSynthesis.speak(passageUtteranceRef);
        set((state) => {
          state.isSpeakingPassage = true;
          state.isPaused = false;
        });
      }
    }
  },

  stopPassageSpeech: () => {
    const { isSpeechSupported } = get();
    if (isSpeechSupported && typeof window !== 'undefined') {
      window.speechSynthesis.cancel();
    }
    set((state) => {
      state.isSpeakingPassage = false;
      state.isPaused = false;
      state.currentWordIndex = null;
      state.passageUtteranceRef = null;
      state.wordsRef = [];
    });
  },

  handleStop: () => {
    get().stopPassageSpeech();
  },

  handlePlayPause: () => {
    const {
      isSpeechSupported,
      quizData,
      generatedPassageLanguage,
      isSpeakingPassage,
      isPaused,
      volume,
      stopPassageSpeech,
    } = get();

    if (!isSpeechSupported || !quizData?.paragraph || !generatedPassageLanguage) return;

    if (isSpeakingPassage) {
      if (isPaused) {
        window.speechSynthesis.resume();
        set((state) => {
          state.isPaused = false;
        });
      } else {
        window.speechSynthesis.pause();
        set((state) => {
          state.isPaused = true;
        });
      }
    } else {
      stopPassageSpeech();

      const words = quizData.paragraph.split(/\s+/);
      set((state) => {
        state.wordsRef = words;
      });

      const utterance = new SpeechSynthesisUtterance(quizData.paragraph);
      utterance.lang = SPEECH_LANGUAGES[generatedPassageLanguage];
      utterance.volume = volume;

      const selectedVoiceURI = get().selectedVoiceURI;
      const selectedVoice = selectedVoiceURI
        ? window.speechSynthesis.getVoices().find((v) => v.voiceURI === selectedVoiceURI)
        : null;

      if (selectedVoice) {
        utterance.voice = selectedVoice;
      }

      utterance.onboundary = (event) => {
        if (event.name === 'word') {
          const charIndex = event.charIndex;
          const wordsUpToChar = quizData.paragraph.substring(0, charIndex).split(/\s+/);
          const currentWordIdx = wordsUpToChar.length - 1;
          set((state) => {
            state.currentWordIndex = currentWordIdx;
          });
        }
      };

      utterance.onend = () => {
        set((state) => {
          state.isSpeakingPassage = false;
          state.isPaused = false;
          state.currentWordIndex = null;
          state.passageUtteranceRef = null;
          state.wordsRef = [];
        });
      };

      utterance.onerror = (event: SpeechSynthesisErrorEvent) => {
        const logPayload = {
          event,
          text: quizData.paragraph.substring(0, 100) + '...',
          voiceURI: utterance.voice?.voiceURI,
          lang: utterance.lang,
        };
        if (event.error === 'interrupted') {
          console.info(`Speech synthesis interrupted in handlePlayPause: ${event.error}`);
        } else {
          console.error(`Speech synthesis error in handlePlayPause: ${event.error}`, logPayload);
        }
      };

      set((state) => {
        state.passageUtteranceRef = utterance;
        state.isSpeakingPassage = true;
        state.isPaused = false;
      });
      window.speechSynthesis.speak(utterance);
    }
  },

  speakText: (text, lang) => {
    const { isSpeechSupported, volume } = get();
    if (!isSpeechSupported || !text) return;

    const utterance = new SpeechSynthesisUtterance(text);
    utterance.lang = SPEECH_LANGUAGES[lang];
    utterance.volume = volume;

    const selectedVoiceURI = get().selectedVoiceURI;
    const selectedVoice = selectedVoiceURI
      ? window.speechSynthesis.getVoices().find((v) => v.voiceURI === selectedVoiceURI)
      : null;

    if (selectedVoice) {
      utterance.voice = selectedVoice;
    }

    utterance.onerror = (event: SpeechSynthesisErrorEvent) => {
      const logPayload = {
        event,
        text: text ? text.substring(0, 100) + '...' : '[Text not available]',
        voiceURI: utterance.voice?.voiceURI,
        lang: utterance.lang,
      };
      if (event.error === 'interrupted') {
        console.info(`Speech synthesis interrupted in speakText: ${event.error}`);
      } else {
        console.error(`Speech synthesis error in speakText: ${event.error}`, logPayload);
      }
    };

    window.speechSynthesis.speak(utterance);
  },

  getTranslation: async (word, sourceLang, targetLang): Promise<string | null> => {
    get().setError(null);

    const cleaningRegex = /[^\p{L}\p{N}\s'-]/gu;
    const cleanedWord = word.replace(cleaningRegex, '').trim();

    if (!cleanedWord) {
      return null;
    }
    if (sourceLang === targetLang) {
      return null;
    }

    const cacheKey = `${sourceLang}:${targetLang}:${cleanedWord.toLowerCase()}`;
    const cachedTranslation = get().translationCache.get(cacheKey);

    if (cachedTranslation) {
      return cachedTranslation;
    }

    try {
      const translation = await translateWordWithGoogle(
        cleanedWord.toLowerCase(),
        targetLang,
        sourceLang
      );

      if (translation) {
        set((state) => {
          state.translationCache.set(cacheKey, translation.translation);
        });
      }

      return translation ? translation.translation : null;
    } catch (error: unknown) {
      console.error('Error calling translateWordWithGoogle action:', error);
      get().setError('Translation service failed.');
      return null;
    }
  },

  updateAvailableVoices: (lang) => {
    if (!get().isSpeechSupported || typeof window === 'undefined') return;
    const finalUniqueVoices = filterAndFormatVoices(lang);
    set((state) => {
      state.availableVoices = finalUniqueVoices;
      const currentSelectedVoiceAvailable = finalUniqueVoices.some(
        (v) => v.uri === state.selectedVoiceURI
      );
      if (!currentSelectedVoiceAvailable) {
        state.selectedVoiceURI = finalUniqueVoices.length > 0 ? finalUniqueVoices[0].uri : null;
      }
    });
  },

  setSelectedVoiceURI: (uri) => {
    set((state) => {
      state.selectedVoiceURI = uri;
    });
    if (get().isSpeakingPassage) {
      get().stopPassageSpeech();
    }
  },
});
