import { create } from 'zustand';
import { immer } from 'zustand/middleware/immer';
import { enableMapSet } from 'immer';

import { type UISlice, createUISlice } from './uiSlice';
import { type SettingsSlice, createSettingsSlice } from './settingsSlice';
import { type QuizSlice, createQuizSlice } from './quizSlice';
import { type AudioSlice, createAudioSlice } from './audioSlice';
import { type ProgressSlice, createProgressSlice } from './progressSlice';
import { type QuizData } from '@/lib/domain/schemas';

export { type Language } from '@/contexts/LanguageContext';
export { type CEFRLevel } from '@/config/language-guidance';

export type { QuizData };

export type TextGeneratorState = UISlice & SettingsSlice & QuizSlice & AudioSlice & ProgressSlice;

enableMapSet();

export const useTextGeneratorStore = create<TextGeneratorState>()(
  immer((...args) => ({
    ...createUISlice(...args),
    ...createSettingsSlice(...args),
    ...createQuizSlice(...args),
    ...createAudioSlice(...args),
    ...createProgressSlice(...args),
  }))
);

if (typeof window !== 'undefined') {
  const isSpeechSupported =
    'speechSynthesis' in window && typeof SpeechSynthesisUtterance !== 'undefined';
  useTextGeneratorStore.getState()._setIsSpeechSupported(isSpeechSupported);
  console.log('Speech Synthesis Supported:', isSpeechSupported);
}

export default useTextGeneratorStore;
