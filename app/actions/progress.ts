'use server';

import { getServerSession } from 'next-auth/next';
import { authOptions } from 'app/features/auth/authOptions';
import { z } from 'zod';
import {
  QuizDataSchema,
  SubmitAnswerResultSchema,
  SessionUserSchema,
  SessionUser,
} from 'app/domain/schemas';
import { findQuizById } from 'app/repo/quizRepo';
import {
  getProgress as findUserProgress,
  initializeProgress,
  updateProgress as updateProgressRepository,
  STREAK_THRESHOLD_FOR_LEVEL_UP,
} from 'app/repo/progressRepo';
import { createFeedback } from 'app/repo/feedbackRepo';
import { CEFR_LEVELS, ProgressUpdateResult } from 'app/domain/progress';
import { CEFRLevel, CEFR_LEVEL_INDICES } from 'app/domain/language-guidance';
import { extractZodErrors } from 'app/utils/errorUtils';

export const getAuthenticatedSessionUser = async (): Promise<SessionUser | null> => {
  const session = await getServerSession(authOptions);
  const user = session?.user;
  const parsed = SessionUserSchema.safeParse(user);
  if (!parsed.success) return null;
  return parsed.data;
};

const DEFAULT_CEFR_LEVEL = 'A1';

const calculateNextProgress = (
  currentLevel: CEFRLevel,
  currentStreak: number,
  isCorrect: boolean
) => {
  if (!isCorrect) {
    return { nextLevel: currentLevel, nextStreak: 0, leveledUp: false };
  }

  const newStreak = currentStreak + 1;

  if (newStreak >= STREAK_THRESHOLD_FOR_LEVEL_UP) {
    const currentLevelIndex = CEFR_LEVEL_INDICES[currentLevel];
    if (currentLevelIndex < CEFR_LEVELS.length - 1) {
      return {
        nextLevel: CEFR_LEVELS[currentLevelIndex + 1],
        nextStreak: 0,
        leveledUp: true,
      };
    }
    return { nextLevel: currentLevel, nextStreak: 0, leveledUp: false };
  }

  return { nextLevel: currentLevel, nextStreak: newStreak, leveledUp: false };
};

const getOrInitProgress = (userId: number, languageCode: string) => {
  const currentProgress = findUserProgress(userId, languageCode);
  return currentProgress || initializeProgress(userId, languageCode);
};

const calculateAndUpdateProgress = (
  userId: number,
  language: string,
  isCorrect: boolean
): ProgressUpdateResult => {
  try {
    const languageCode = language.toLowerCase().slice(0, 2);
    const currentProgress = getOrInitProgress(userId, languageCode);
    const { nextLevel, nextStreak, leveledUp } = calculateNextProgress(
      currentProgress.cefr_level,
      currentProgress.correct_streak,
      isCorrect
    );
    updateProgressRepository(userId, languageCode, nextLevel, nextStreak);
    return { currentLevel: nextLevel, currentStreak: nextStreak, leveledUp };
  } catch (e) {
    const message = e instanceof Error ? e.message : 'Unknown error';
    console.error(
      `[calculateAndUpdateProgress] Error for user ${userId}, lang ${language}, isCorrect ${isCorrect}: ${message}`
    );
    return {
      currentLevel: DEFAULT_CEFR_LEVEL,
      currentStreak: 0,
      leveledUp: false,
      error: `Error updating progress for user ${userId}. Details: ${message}`,
    };
  }
};

const updateProgressSchema = z.object({
  isCorrect: z.boolean(),
  language: z.string().min(2).max(5),
});

const getProgressSchema = z.object({
  language: z.string().min(2).max(5),
});

const submitAnswerSchema = z.object({
  ans: z.string().length(1).optional(),
  learn: z.string().min(2).max(5),
  lang: z.string().min(2).max(5),
  id: z.number().int().positive(),
  cefrLevel: z.string().optional(),
});

const submitFeedbackSchema = z.object({
  quizId: z.number().int().positive(),
  is_good: z.number().int().min(0).max(1),
  userAnswer: z.string().optional(),
  isCorrect: z.boolean().optional(),
  passageLanguage: z.string(),
  questionLanguage: z.string(),
  currentLevel: z.string(),
});

export type UpdateProgressParams = z.infer<typeof updateProgressSchema>;
export type GetProgressParams = z.infer<typeof getProgressSchema>;
export type SubmitFeedbackParams = z.infer<typeof submitFeedbackSchema>;

type FeedbackType = z.infer<typeof SubmitAnswerResultSchema>['feedback'];

export interface ProgressResponse {
  currentLevel: string;
  currentStreak: number;
  leveledUp?: boolean;
  error?: string;
  feedback?: FeedbackType;
}

const getParsedQuizData = (quizId: number) => {
  try {
    const quizRecord = findQuizById(quizId);
    if (!quizRecord) return { data: null, error: `Quiz with ID ${quizId} not found.` };
    const parsedContent = QuizDataSchema.safeParse(quizRecord.content);
    if (!parsedContent.success)
      return {
        data: null,
        error: `Failed to parse content for quiz ID ${quizId} against QuizDataSchema.`,
      };
    return { data: parsedContent.data };
  } catch (e) {
    const message = e instanceof Error ? e.message : 'Unknown error';
    console.error(`[getParsedQuizData] Error parsing quiz data for ID ${quizId}: ${message}`);
    return { data: null, error: `Error processing quiz data for ID ${quizId}.` };
  }
};

const generateFeedback = (
  fullQuizData: z.infer<typeof QuizDataSchema>,
  userAnswer: string | undefined
) => {
  const correctAnswerKey = fullQuizData.correctAnswer as keyof typeof fullQuizData.options | null;
  const allExplanations = fullQuizData.allExplanations;
  const options = fullQuizData.options;
  if (
    typeof userAnswer === 'string' &&
    userAnswer in options &&
    correctAnswerKey &&
    allExplanations
  ) {
    const chosenAnswerKey = userAnswer as keyof typeof options;
    const isCorrect = chosenAnswerKey === correctAnswerKey;
    const correctExplanation = allExplanations[correctAnswerKey];
    const relevantText = fullQuizData.relevantText;
    let chosenIncorrectExplanation: string | undefined | null = null;
    if (!isCorrect) chosenIncorrectExplanation = allExplanations[chosenAnswerKey];
    if (correctExplanation && relevantText) {
      return {
        isCorrect,
        feedbackData: {
          isCorrect,
          correctAnswer: correctAnswerKey,
          correctExplanation,
          chosenIncorrectExplanation,
          relevantText,
        },
      };
    }
  }
  return { isCorrect: false, feedbackData: undefined };
};

export const updateProgress = async (params: UpdateProgressParams): Promise<ProgressResponse> => {
  const sessionUser = await getAuthenticatedSessionUser();
  const userId = sessionUser?.dbId ?? null;
  if (userId === null)
    return { currentLevel: DEFAULT_CEFR_LEVEL, currentStreak: 0, error: 'Unauthorized' };
  const parsedBody = updateProgressSchema.safeParse(params);
  if (!parsedBody.success) {
    return {
      currentLevel: DEFAULT_CEFR_LEVEL,
      currentStreak: 0,
      error: `Invalid parameters: ${extractZodErrors(parsedBody.error)}`,
    };
  }
  const { isCorrect, language } = parsedBody.data;
  const progressResult = calculateAndUpdateProgress(userId, language, isCorrect);
  return {
    currentLevel: progressResult.currentLevel,
    currentStreak: progressResult.currentStreak,
    leveledUp: progressResult.leveledUp,
    ...(progressResult.error && { error: progressResult.error }),
  };
};

export const submitAnswer = async (
  params: z.infer<typeof submitAnswerSchema>
): Promise<ProgressResponse> => {
  const sessionUser = await getAuthenticatedSessionUser();
  const userId = sessionUser?.dbId ?? null;

  const parsedBody = submitAnswerSchema.safeParse(params);
  if (!parsedBody.success) {
    return {
      currentLevel: DEFAULT_CEFR_LEVEL,
      currentStreak: 0,
      error: `Invalid request parameters: ${extractZodErrors(parsedBody.error)}`,
    };
  }

  const { ans, id, learn, cefrLevel: requestCefrLevel } = parsedBody.data;

  const { data: fullQuizData, error: quizError } = getParsedQuizData(id);
  if (quizError || !fullQuizData) {
    return {
      currentLevel: requestCefrLevel || DEFAULT_CEFR_LEVEL,
      currentStreak: 0,
      error: quizError || `Quiz data unavailable for ID ${id}.`,
    };
  }

  const { isCorrect, feedbackData } = generateFeedback(fullQuizData, ans);

  const baseResponse: ProgressResponse = {
    currentLevel: requestCefrLevel || DEFAULT_CEFR_LEVEL,
    currentStreak: 0,
    leveledUp: false,
    feedback: feedbackData,
  };

  if (userId === null) {
    return baseResponse;
  }

  const progressUpdate = calculateAndUpdateProgress(userId, learn, isCorrect);
  return {
    ...baseResponse,
    currentLevel: progressUpdate.currentLevel,
    currentStreak: progressUpdate.currentStreak,
    leveledUp: progressUpdate.leveledUp,
    ...(progressUpdate.error && { error: progressUpdate.error }),
  };
};

export const getProgress = async (params: GetProgressParams): Promise<ProgressResponse> => {
  const sessionUser = await getAuthenticatedSessionUser();
  const userId = sessionUser?.dbId ?? null;
  if (userId === null)
    return {
      currentLevel: DEFAULT_CEFR_LEVEL,
      currentStreak: 0,
      error: 'Unauthorized: User not logged in.',
    };
  const parsedParams = getProgressSchema.safeParse(params);
  if (!parsedParams.success)
    return {
      currentLevel: DEFAULT_CEFR_LEVEL,
      currentStreak: 0,
      error: 'Invalid parameters provided.',
    };
  const { language } = parsedParams.data;
  let currentLevel = DEFAULT_CEFR_LEVEL;
  let currentStreak = 0;
  const languageCode = language.toLowerCase().slice(0, 2);
  try {
    const progressRecord = findUserProgress(userId, languageCode);
    if (progressRecord) {
      currentLevel = progressRecord.cefr_level;
      currentStreak = progressRecord.correct_streak;
    }
  } catch (error: unknown) {
    console.error(
      `[getProgress] Repository error for user ${userId}, lang ${languageCode}:`,
      error
    );
    return {
      currentLevel: DEFAULT_CEFR_LEVEL,
      currentStreak: 0,
      leveledUp: false,
      error: `Error fetching progress: ${error instanceof Error ? error.message : 'Unknown repository error'}`,
    };
  }
  return { currentLevel, currentStreak, leveledUp: false };
};

export interface SubmitFeedbackResponse {
  success: boolean;
  error?: string;
  cached?: boolean;
}

export const submitFeedback = async (
  params: SubmitFeedbackParams
): Promise<SubmitFeedbackResponse> => {
  const sessionUser = await getAuthenticatedSessionUser();
  const userId = sessionUser?.dbId ?? null;
  if (userId === null) return { success: false, error: 'Unauthorized' };
  const parsedBody = submitFeedbackSchema.safeParse(params);
  if (!parsedBody.success) return { success: false, error: 'Invalid parameters' };
  const { quizId, is_good, userAnswer, isCorrect } = parsedBody.data;
  try {
    const quizExists = findQuizById(quizId);
    if (!quizExists) return { success: false, error: `Quiz not found.` };
    const feedbackData = {
      quiz_id: quizId,
      user_id: userId,
      is_good: is_good === 1,
      user_answer: userAnswer,
      is_correct: isCorrect === undefined ? undefined : isCorrect,
    };
    createFeedback(feedbackData);
    return { success: true };
  } catch (error) {
    console.error(
      `[submitFeedback] Repository error for quizId ${quizId}, userId ${userId}:`,
      error
    );
    return {
      success: false,
      error: `Repository error while saving feedback: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
};
