import type { StateCreator } from 'zustand';
import { type LearningLanguage } from '@/config/languages';
import { type CEFRLevel } from '@/config/language-guidance';
import type { Language, TextGeneratorState } from './textGeneratorStore';

export interface SettingsSlice {
  passageLanguage: LearningLanguage;
  generatedPassageLanguage: LearningLanguage | null;
  generatedQuestionLanguage: Language | null;
  cefrLevel: CEFRLevel;
  setPassageLanguage: (lang: LearningLanguage) => void;
  setGeneratedPassageLanguage: (lang: LearningLanguage | null) => void;
  setGeneratedQuestionLanguage: (lang: Language | null) => void;
  setCefrLevel: (level: CEFRLevel) => void;
}

export const createSettingsSlice: StateCreator<
  TextGeneratorState,
  [['zustand/immer', never]],
  [],
  SettingsSlice
> = (set, get) => ({
  passageLanguage: 'en',
  generatedPassageLanguage: null,
  generatedQuestionLanguage: null,
  cefrLevel: 'A1',

  setGeneratedPassageLanguage: (lang) =>
    set((state) => {
      state.generatedPassageLanguage = lang;
    }),
  setGeneratedQuestionLanguage: (lang) =>
    set((state) => {
      state.generatedQuestionLanguage = lang;
    }),
  setCefrLevel: (level) =>
    set((state) => {
      state.cefrLevel = level;
    }),

  setPassageLanguage: (lang) => {
    get().stopPassageSpeech();

    set((state) => {
      state.passageLanguage = lang;
      state.quizData = null;
      state.selectedAnswer = null;
      state.isAnswered = false;
      state.showExplanation = false;
      state.showQuestionSection = false;
      state.currentWordIndex = null;
      state.relevantTextRange = null;
      state.error = null;
      state.loading = false;
      state.showContent = false;
      state.generatedPassageLanguage = null;
      state.nextQuizAvailable = null;
    });

    void get().fetchUserProgress();
  },
});
