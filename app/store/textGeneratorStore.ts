import { create } from 'zustand';
import { z } from 'zod';
import { type Language, LANGUAGES, SPEECH_LANGUAGES } from '../contexts/LanguageContext';
import { type CEFRLevel } from '../config/language-guidance';
import { getRandomTopicForLevel } from '../config/topics';
import { getVocabularyGuidance, getGrammarGuidance } from '../config/language-guidance';

// Quiz data schema
const quizDataSchema = z.object({
  paragraph: z.string(),
  question: z.string(),
  options: z.object({
    A: z.string(),
    B: z.string(),
    C: z.string(),
    D: z.string(),
  }),
  explanations: z.object({
    A: z.string(),
    B: z.string(),
    C: z.string(),
    D: z.string(),
  }),
  correctAnswer: z.string(),
  relevantText: z.string(),
  topic: z.string(),
});

export type QuizData = z.infer<typeof quizDataSchema>;

// API response schema
const apiResponseSchema = z.object({
  result: z.string().optional(),
  error: z.string().optional(),
});

interface TranslationResponse {
  responseStatus: number;
  responseData: {
    translatedText: string;
  };
}

// Progress response type
interface UserProgressResponse {
  currentLevel: CEFRLevel;
  currentStreak: number;
  leveledUp?: boolean;
}

interface TextGeneratorState {
  // UI state
  loading: boolean;
  error: string | null;
  showLoginPrompt: boolean;
  showContent: boolean;
  showQuestionSection: boolean;
  showExplanation: boolean;
  isProgressLoading: boolean;

  // Language/settings state
  passageLanguage: Language;
  generatedPassageLanguage: Language | null;
  generatedQuestionLanguage: Language | null;
  cefrLevel: CEFRLevel;

  // Quiz state
  quizData: QuizData | null;
  selectedAnswer: string | null;
  isAnswered: boolean;
  relevantTextRange: { start: number; end: number } | null;

  // Audio state
  isSpeechSupported: boolean;
  isSpeakingPassage: boolean;
  isPaused: boolean;
  volume: number;
  currentWordIndex: number | null;

  // User state
  userStreak: number | null;

  // Refs to maintain
  passageUtteranceRef: SpeechSynthesisUtterance | null;
  wordsRef: string[];
  questionDelayTimeoutRef: NodeJS.Timeout | null;

  // Actions
  setShowLoginPrompt: (show: boolean) => void;
  setPassageLanguage: (lang: Language) => void;
  setCefrLevel: (level: CEFRLevel) => void;
  setVolumeLevel: (volume: number) => void;
  fetchUserProgress: () => Promise<void>;
  generateText: () => Promise<void>;
  handleAnswerSelect: (answer: string) => Promise<void>;
  stopPassageSpeech: () => void;
  handlePlayPause: () => void;
  handleStop: () => void;
  getTranslation: (word: string, sourceLang: string, targetLang: string) => Promise<string>;
  speakText: (text: string | null, lang: Language) => void;
}

export const useTextGeneratorStore = create<TextGeneratorState>((set, get) => ({
  // Initial state
  loading: false,
  error: null,
  showLoginPrompt: true,
  showContent: true,
  showQuestionSection: false,
  showExplanation: false,
  isProgressLoading: false,

  passageLanguage: 'en',
  generatedPassageLanguage: null,
  generatedQuestionLanguage: null,
  cefrLevel: 'A1',

  quizData: null,
  selectedAnswer: null,
  isAnswered: false,
  relevantTextRange: null,

  isSpeechSupported: false,
  isSpeakingPassage: false,
  isPaused: false,
  volume: 0.5,
  currentWordIndex: null,

  userStreak: null,

  passageUtteranceRef: null,
  wordsRef: [],
  questionDelayTimeoutRef: null,

  // Simple setters
  setShowLoginPrompt: (show) => set({ showLoginPrompt: show }),
  setPassageLanguage: (lang) => set({ passageLanguage: lang }),
  setCefrLevel: (level) => set({ cefrLevel: level }),

  setVolumeLevel: (volume) => {
    set({ volume });
    const { passageUtteranceRef } = get();

    if (passageUtteranceRef) {
      passageUtteranceRef.volume = volume;
    }

    if (window.speechSynthesis.speaking) {
      window.speechSynthesis.cancel();
      if (passageUtteranceRef) {
        passageUtteranceRef.volume = volume;
        window.speechSynthesis.speak(passageUtteranceRef);
        set({ isSpeakingPassage: true, isPaused: false });
      }
    }
  },

  // Stop speech
  stopPassageSpeech: () => {
    const { isSpeechSupported } = get();
    if (isSpeechSupported) {
      window.speechSynthesis.cancel();
      set({
        isSpeakingPassage: false,
        isPaused: false,
        currentWordIndex: null,
        passageUtteranceRef: null,
      });
    }
  },

  // Play/pause speech
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
        set({ isPaused: false });
      } else {
        window.speechSynthesis.pause();
        set({ isPaused: true });
      }
    } else {
      stopPassageSpeech();

      const words = quizData.paragraph.split(/\s+/);
      set({ wordsRef: words });

      const utterance = new SpeechSynthesisUtterance(quizData.paragraph);
      utterance.lang = SPEECH_LANGUAGES[generatedPassageLanguage];
      utterance.volume = volume;

      set({ passageUtteranceRef: utterance });

      utterance.onboundary = (event) => {
        if (event.name === 'word') {
          let wordIndex = 0;
          let charCount = 0;
          for (let i = 0; i < words.length; i++) {
            charCount += words[i].length + 1;
            if (charCount > event.charIndex) {
              wordIndex = i;
              break;
            }
          }
          set({ currentWordIndex: wordIndex });
        }
      };

      utterance.onend = () => {
        set({
          isSpeakingPassage: false,
          isPaused: false,
          currentWordIndex: null,
          passageUtteranceRef: null,
        });
      };

      utterance.onerror = (event) => {
        if (event.error !== 'interrupted') {
          console.error('Speech synthesis error (passage):', event.error);
          set({
            isSpeakingPassage: false,
            isPaused: false,
            currentWordIndex: null,
            passageUtteranceRef: null,
          });
        }
      };

      window.speechSynthesis.speak(utterance);
      set({ isSpeakingPassage: true, isPaused: false });
    }
  },

  // Stop button handler
  handleStop: () => {
    const { stopPassageSpeech } = get();
    stopPassageSpeech();
  },

  // Speak a single word
  speakText: (text, lang) => {
    const { isSpeechSupported, stopPassageSpeech, volume } = get();

    if (!isSpeechSupported || !text) {
      return;
    }

    stopPassageSpeech();

    const utterance = new SpeechSynthesisUtterance(text);
    utterance.lang = SPEECH_LANGUAGES[lang];
    utterance.volume = volume;

    utterance.onerror = (event) => {
      console.error('Speech synthesis error (word):', event.error);
    };

    window.speechSynthesis.speak(utterance);
  },

  // Translation service
  getTranslation: async (word, sourceLang, targetLang) => {
    try {
      const response = await fetch(
        `https://api.mymemory.translated.net/get?q=${encodeURIComponent(word)}&langpair=${sourceLang}|${targetLang}`
      );

      if (!response.ok) throw new Error('Translation failed');

      const data = (await response.json()) as TranslationResponse;
      if (data.responseStatus === 200 && data.responseData?.translatedText) {
        return data.responseData.translatedText;
      }
      throw new Error('No translation available');
    } catch (error) {
      console.error('Translation error:', error);
      return word; // Return original word on error
    }
  },

  // Fetch user progress
  fetchUserProgress: async () => {
    const { passageLanguage } = get();
    set({ isProgressLoading: true });

    try {
      const response = await fetch(`/api/user/progress?language=${passageLanguage}`);

      if (response.ok) {
        const data = (await response.json()) as UserProgressResponse;

        if (data.currentLevel) {
          set({ cefrLevel: data.currentLevel });
        }
        set({ userStreak: data.currentStreak ?? 0 });
        console.log(`[Progress] Fetched user progress for ${passageLanguage}:`, data);
      } else {
        let errorMsg = `Failed to fetch user progress (${response.status})`;
        try {
          const errorText = await response.text();
          const errorData = JSON.parse(errorText) as { message?: string; error?: string };
          errorMsg = errorData?.message || errorData?.error || errorMsg;
        } catch (errorParsingOrReadingError) {
          console.warn(
            '[Progress Fetch] Could not parse error response JSON or read text:',
            errorParsingOrReadingError
          );
        }
        throw new Error(errorMsg);
      }
    } catch (err) {
      console.error(`[Progress] Error fetching user progress for ${passageLanguage}:`, err);
      set({ cefrLevel: 'A1', userStreak: 0 });
    } finally {
      set({ isProgressLoading: false });
    }
  },

  // Generate text
  generateText: async () => {
    const { stopPassageSpeech, passageLanguage, cefrLevel, questionDelayTimeoutRef } = get();

    // First hide content with animation
    set({ showContent: false });

    // Wait for exit animation to complete
    setTimeout(async () => {
      stopPassageSpeech();
      set({
        loading: true,
        error: null,
        quizData: null,
        selectedAnswer: null,
        isAnswered: false,
        showExplanation: false,
        showQuestionSection: false,
        currentWordIndex: null,
        relevantTextRange: null,
      });

      if (questionDelayTimeoutRef) {
        clearTimeout(questionDelayTimeoutRef);
        set({ questionDelayTimeoutRef: null });
      }

      const levelToUse = cefrLevel;

      try {
        // Get a random topic appropriate for the current CEFR level
        const randomTopic = getRandomTopicForLevel(levelToUse);

        // Get vocabulary and grammar guidance for the current level
        const vocabGuidance = getVocabularyGuidance(levelToUse);
        const grammarGuidance = getGrammarGuidance(levelToUse);

        const passageLanguageName = LANGUAGES[passageLanguage] || passageLanguage;
        // We need to get the questionLanguage from the context at runtime
        // This will be provided by the component
        const questionLanguage = get().generatedQuestionLanguage || 'en';
        const questionLanguageName = LANGUAGES[questionLanguage] || questionLanguage;

        // Add language guidance to the prompt for A1 and A2 levels
        let languageInstructions = '';
        if (['A1', 'A2'].includes(levelToUse)) {
          languageInstructions = `\n\nVocabulary guidance: ${vocabGuidance}\n\nGrammar guidance: ${grammarGuidance}`;
        }

        const prompt = `Generate a reading passage in ${passageLanguageName} suitable for CEFR level ${levelToUse} about the topic "${randomTopic}". The passage should be interesting and typical for language learners at this stage. After the passage, provide a multiple-choice comprehension question about it, four answer options (A, B, C, D), indicate the correct answer letter, provide a brief topic description (3-5 words in English) for image generation, provide explanations for each option being correct or incorrect, and include the relevant text snippet from the passage supporting the correct answer. Format the question, options, and explanations in ${questionLanguageName}. Respond ONLY with the JSON object.${languageInstructions}`;

        const seed = Math.floor(Math.random() * 100);

        console.log('[API] Sending request with prompt:', prompt.substring(0, 100) + '...');
        console.log(
          '[API] Passage Lang:',
          passageLanguage,
          'Question Lang:',
          questionLanguage,
          'Level:',
          levelToUse,
          'Topic:',
          randomTopic
        );

        const MAX_RETRIES = 2;
        let currentRetry = 0;
        let forceCache = false;
        let success = false;

        // Keep trying until we succeed or exhaust all options
        while (!success && (currentRetry <= MAX_RETRIES || !forceCache)) {
          try {
            const requestBody = {
              prompt,
              seed,
              passageLanguage,
              questionLanguage,
              forceCache,
            };

            const response = await fetch('/api/chat', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(requestBody),
            });

            if (!response.ok) {
              // Define a simple type for the expected error structure
              type ErrorResponse = { error?: string; message?: string };
              let errorData: ErrorResponse = {};
              try {
                // Try to parse the error response body
                errorData = (await response.json()) as ErrorResponse;
              } catch (parseError) {
                console.warn('Could not parse error response JSON:', parseError);
                // If parsing fails, use the status text or a default message
                throw new Error(response.statusText || `HTTP error! status: ${response.status}`);
              }
              // Use the parsed error message if available
              throw new Error(
                errorData.error || errorData.message || `HTTP error! status: ${response.status}`
              );
            }

            // Await the JSON response first, then parse
            const jsonResponse = (await response.json()) as unknown;
            const data = apiResponseSchema.parse(jsonResponse);

            if (data.error || !data.result) {
              throw new Error(data.error || 'No result received');
            }

            // Clean up the string response from the AI before parsing
            const jsonString = data.result.replace(/```json|```/g, '').trim();

            // Use Zod's pipeline for safe JSON parsing - this avoids direct JSON.parse entirely
            const parsedResult = z
              .string()
              .transform((str) => {
                try {
                  return JSON.parse(str) as unknown;
                } catch (e) {
                  throw new Error(`Failed to parse JSON: ${String(e)}`);
                }
              })
              .pipe(quizDataSchema)
              .safeParse(jsonString);

            if (!parsedResult.success) {
              console.error('Error parsing generated quiz JSON:', parsedResult.error);
              throw new Error('Failed to parse the structure of the generated quiz.');
            }

            // No need to cast - Zod guarantees the type
            const validatedData = parsedResult.data;

            set({
              quizData: validatedData,
              generatedPassageLanguage: passageLanguage,
            });

            // --- Calculate Dynamic Question Delay ---
            const WPM = 250; // Lower WPM for a quicker appearance
            const wordCount = validatedData.paragraph.split(/\s+/).filter(Boolean).length;
            const readingTimeMs = (wordCount / WPM) * 60 * 1000;
            const bufferMs = 1500; // Further reduce buffer for a more responsive feel
            const minDelayMs = 1500; // Shorter minimum delay
            const questionDelayMs = Math.max(minDelayMs, readingTimeMs + bufferMs);
            console.log(
              `[DelayCalc] Words: ${wordCount}, Est. Read Time: ${readingTimeMs.toFixed(0)}ms, Delay Set: ${questionDelayMs.toFixed(0)}ms`
            );
            // --- End Calculate Delay ---

            // Start timer to show question section using calculated delay, but with a cross-fade effect
            const timeoutId = setTimeout(() => {
              // When it's time to show the question, first make sure content is visible
              if (!get().showContent) set({ showContent: true });

              // Short delay to ensure content is visible before showing question
              setTimeout(() => {
                set({ showQuestionSection: true });
              }, 100);
            }, questionDelayMs);

            set({ questionDelayTimeoutRef: timeoutId });
            success = true;
          } catch (err) {
            console.error(`Error during attempt ${currentRetry + 1}:`, err);
            if (currentRetry < MAX_RETRIES) {
              // If we have retries left, increment the counter and try again
              currentRetry++;
              console.log(`Retrying... Attempt ${currentRetry + 1} of ${MAX_RETRIES + 1}`);
              const delay = Math.pow(2, currentRetry) * 1000; // Exponential backoff
              await new Promise((resolve) => setTimeout(resolve, delay));
            } else if (!forceCache) {
              // We've exhausted our retries, try the cache as last resort
              console.log('Retries exhausted, trying to force cache retrieval');
              forceCache = true;
              currentRetry = 0; // Reset retry counter for the cache attempt
            } else {
              // We've tried retries and cache, now show error
              if (err instanceof Error) {
                set({ error: err.message });
              } else {
                set({ error: 'An error occurred during text generation' });
              }
              throw err; // Re-throw to exit the retry loop
            }
          }
        }
      } catch (err) {
        console.error('All attempts failed:', err);
      } finally {
        set({ loading: false, showContent: true });
      }
    }, 300);
  },

  // Handle answer selection
  handleAnswerSelect: async (answer) => {
    const { quizData, isAnswered, stopPassageSpeech, generatedPassageLanguage, userStreak } = get();

    if (isAnswered || !quizData) return;

    stopPassageSpeech();
    set({
      selectedAnswer: answer,
      isAnswered: true,
      showExplanation: false,
      relevantTextRange: null, // Reset range initially
    });

    // Find and set the relevant text range
    if (quizData.relevantText && quizData.paragraph) {
      const startIndex = quizData.paragraph.indexOf(quizData.relevantText);
      if (startIndex !== -1) {
        set({
          relevantTextRange: {
            start: startIndex,
            end: startIndex + quizData.relevantText.length,
          },
        });
        console.log(
          `[Highlight] Relevant text range found: ${startIndex} - ${startIndex + quizData.relevantText.length}`
        );
      } else {
        console.warn(
          '[Highlight] Relevant text not found exactly in paragraph:',
          quizData.relevantText
        );
      }
    }

    // Update user progress if authenticated
    try {
      const response = await fetch('/api/user/progress', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          isCorrect: answer === quizData.correctAnswer,
          language: generatedPassageLanguage,
        }),
      });

      if (response.ok) {
        const progressData = (await response.json()) as UserProgressResponse;

        if (progressData) {
          set({ userStreak: progressData.currentStreak });

          // First check for level up
          if (progressData.leveledUp) {
            set({ cefrLevel: progressData.currentLevel });
            console.log(`[Progress] Leveled up to ${progressData.currentLevel}!`);
          }
        }
      } else {
        let errorMsg = `Failed to update progress (${response.status})`;
        try {
          const errorText = await response.text();
          const errorData = JSON.parse(errorText) as { message?: string; error?: string };
          errorMsg = errorData?.message || errorData?.error || errorMsg;
        } catch (errorParsingOrReadingError) {
          console.warn(
            '[Progress Update] Could not parse error response JSON or read text:',
            errorParsingOrReadingError
          );
        }
        console.error(`[Progress] Error: ${errorMsg}`);
      }
    } catch (err) {
      console.error('[Progress] Error updating progress:', err);
    }

    setTimeout(() => set({ showExplanation: true }), 100);
  },
}));

export default useTextGeneratorStore;
