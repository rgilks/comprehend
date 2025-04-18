'use server';

import { getServerSession } from 'next-auth/next';
import type { Session } from 'next-auth';
import { authOptions } from '@/lib/authOptions';
import db from '@/lib/db';
import { z } from 'zod';
import { QuizDataSchema, SubmitAnswerResultSchema } from '@/lib/domain/schemas';
import * as Sentry from '@sentry/nextjs';

interface SessionUser extends NonNullable<Session['user']> {
  dbId?: number;
}

const CEFR_LEVELS: ReadonlyArray<string> = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2'];

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
  id: z.number().int().positive().optional(),
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

function calculateAndUpdateProgress(
  userId: number,
  language: string,
  isCorrect: boolean
): { currentLevel: string; currentStreak: number; leveledUp: boolean; dbError?: string } {
  const normalizedLanguage = language.toLowerCase().slice(0, 2);

  try {
    const userProgress = db
      .prepare(
        'SELECT cefr_level, correct_streak FROM user_language_progress WHERE user_id = ? AND language_code = ?'
      )
      .get(userId, normalizedLanguage) as
      | { cefr_level: string; correct_streak: number }
      | undefined;

    let current_cefr_level: string;
    let correct_streak: number;

    if (!userProgress) {
      db.prepare('INSERT INTO user_language_progress (user_id, language_code) VALUES (?, ?)').run(
        userId,
        normalizedLanguage
      );
      current_cefr_level = 'A1';
      correct_streak = 0;
    } else {
      current_cefr_level = userProgress.cefr_level;
      correct_streak = userProgress.correct_streak;
    }

    let leveledUp = false;
    if (isCorrect) {
      correct_streak += 1;
      if (correct_streak >= 5) {
        const currentLevelIndex = CEFR_LEVELS.indexOf(current_cefr_level);
        if (currentLevelIndex < CEFR_LEVELS.length - 1) {
          current_cefr_level = CEFR_LEVELS[currentLevelIndex + 1];
          correct_streak = 0;
          leveledUp = true;
        } else {
          correct_streak = 0;
        }
      }
    } else {
      if (correct_streak > 0) {
      }
      correct_streak = 0;
    }

    db.prepare(
      'UPDATE user_language_progress SET cefr_level = ?, correct_streak = ?, last_practiced = CURRENT_TIMESTAMP WHERE user_id = ? AND language_code = ?'
    ).run(current_cefr_level, correct_streak, userId, normalizedLanguage);

    return {
      currentLevel: current_cefr_level,
      currentStreak: correct_streak,
      leveledUp: leveledUp,
    };
  } catch (dbError) {
    Sentry.captureException(dbError, { extra: { userId, language, isCorrect } });
    const message = dbError instanceof Error ? dbError.message : 'Unknown DB error';
    return {
      currentLevel: 'A1',
      currentStreak: 0,
      leveledUp: false,
      dbError: `A database error occurred: ${message}`,
    };
  }
}

export const updateProgress = async (params: UpdateProgressParams): Promise<ProgressResponse> => {
  const session = await getServerSession(authOptions);
  const sessionUser = session?.user as SessionUser | undefined;

  if (!session || !sessionUser?.dbId) {
    return { currentLevel: 'A1', currentStreak: 0, error: 'Unauthorized' };
  }

  const userId = sessionUser.dbId;
  const parsedBody = updateProgressSchema.safeParse(params);

  if (!parsedBody.success) {
    return { currentLevel: 'A1', currentStreak: 0, error: 'Invalid parameters' };
  }

  const { isCorrect, language } = parsedBody.data;

  const progressResult = calculateAndUpdateProgress(userId, language, isCorrect);

  return {
    currentLevel: progressResult.currentLevel,
    currentStreak: progressResult.currentStreak,
    leveledUp: progressResult.leveledUp,
    error: progressResult.dbError,
  };
};

export const submitAnswer = async (
  params: z.infer<typeof submitAnswerSchema>
): Promise<ProgressResponse> => {
  const session = await getServerSession(authOptions);
  const sessionUser = session?.user as SessionUser | undefined;
  const userId = sessionUser?.dbId;

  const parsedBody = submitAnswerSchema.safeParse(params);
  if (!parsedBody.success) {
    const errorDetails = JSON.stringify(parsedBody.error.flatten().fieldErrors);
    return {
      currentLevel: 'A1',
      currentStreak: 0,
      error: `Invalid request parameters: ${errorDetails}`,
    };
  }

  const { ans, id, learn, cefrLevel: requestCefrLevel } = parsedBody.data;

  if (typeof id !== 'number') {
    return {
      currentLevel: 'A1',
      currentStreak: 0,
      error: 'Missing or invalid quiz ID in request.',
    };
  }

  let isCorrect = false;
  let feedbackData: FeedbackType = undefined;

  try {
    const quizRecord = db.prepare('SELECT content FROM quiz WHERE id = ?').get(id) as
      | { content: string }
      | undefined;

    if (!quizRecord) {
      return {
        currentLevel: 'A1',
        currentStreak: 0,
        error: `Quiz with ID ${id} not found.`,
      };
    }

    const parsedContent = QuizDataSchema.safeParse(JSON.parse(quizRecord.content));

    if (!parsedContent.success) {
      console.error(
        `[SubmitAnswer] Failed to parse quiz content (ID: ${id}) using QuizDataSchema: ${JSON.stringify(parsedContent.error.flatten())}`
      );
      return {
        currentLevel: 'A1',
        currentStreak: 0,
        error: `Failed to parse content for quiz ID ${id}.`,
      };
    }

    const fullQuizData = parsedContent.data;

    if (typeof ans === 'string' && ans in fullQuizData.options) {
      isCorrect = ans === fullQuizData.correctAnswer;

      if (
        typeof fullQuizData.correctAnswer === 'string' &&
        fullQuizData.explanations &&
        typeof fullQuizData.relevantText === 'string'
      ) {
        feedbackData = {
          isCorrect: isCorrect,
          correctAnswer: fullQuizData.correctAnswer,
          explanations: fullQuizData.explanations,
          relevantText: fullQuizData.relevantText,
        };
      } else {
        feedbackData = undefined;
      }
    } else {
      feedbackData = undefined;
    }
  } catch (error: unknown) {
    console.error(`[SubmitAnswer] Error processing quiz ID ${id}:`, error);
    Sentry.captureException(error, { extra: { quizId: id } });
    return {
      currentLevel: 'A1',
      currentStreak: 0,
      error: `Error processing answer for quiz ${id}: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }

  const responsePayload: ProgressResponse = {
    currentLevel: 'A1',
    currentStreak: 0,
    leveledUp: false,
    feedback: feedbackData,
  };

  if (userId) {
    try {
      const progressUpdate = calculateAndUpdateProgress(userId, learn, isCorrect);

      responsePayload.currentLevel = progressUpdate.currentLevel;
      responsePayload.currentStreak = progressUpdate.currentStreak;
      responsePayload.leveledUp = progressUpdate.leveledUp;
      if (progressUpdate.dbError) {
        console.error(
          `[SubmitAnswer] DB Error during progress update for user ${userId}: ${progressUpdate.dbError}`
        );
      }
    } catch (dbError) {
      console.error(
        `[SubmitAnswer] Database error during progress update for user ${userId}:`,
        dbError
      );
      responsePayload.error =
        (responsePayload.error ? responsePayload.error + '; ' : '') +
        'Failed to update user progress.';
    }
  } else {
    responsePayload.currentLevel = requestCefrLevel || 'A1';
    responsePayload.currentStreak = 0;
    responsePayload.leveledUp = false;
  }

  return responsePayload;
};

export const getProgress = async (params: GetProgressParams): Promise<ProgressResponse> => {
  const session = await getServerSession(authOptions);
  const sessionUser = session?.user as SessionUser | undefined;

  if (!session || !sessionUser?.dbId) {
    return {
      currentLevel: 'A1',
      currentStreak: 0,
      error: 'Unauthorized: User not logged in.',
    };
  }

  const userId = sessionUser.dbId;
  const parsedParams = getProgressSchema.safeParse(params);

  if (!parsedParams.success) {
    return {
      currentLevel: 'A1',
      currentStreak: 0,
      error: 'Invalid parameters provided.',
    };
  }

  const normalizedLanguage = parsedParams.data.language.toLowerCase().slice(0, 2);

  try {
    const userProgress = db
      .prepare(
        'SELECT cefr_level, correct_streak FROM user_language_progress WHERE user_id = ? AND language_code = ?'
      )
      .get(userId, normalizedLanguage) as
      | { cefr_level: string; correct_streak: number }
      | undefined;

    if (!userProgress) {
      return {
        currentLevel: 'A1',
        currentStreak: 0,
      };
    }

    return {
      currentLevel: userProgress.cefr_level,
      currentStreak: userProgress.correct_streak,
    };
  } catch (dbError) {
    console.error(
      `[GetProgress] Database error for user ${userId}, language ${normalizedLanguage}:`,
      dbError
    );
    Sentry.captureException(dbError, { extra: { userId, language: normalizedLanguage } });
    const message = dbError instanceof Error ? dbError.message : 'Unknown DB error';
    return {
      currentLevel: 'A1',
      currentStreak: 0,
      error: `Failed to get progress: ${message}`,
    };
  }
};

export interface SubmitFeedbackResponse {
  success: boolean;
  error?: string;
  cached?: boolean;
}

export const submitQuestionFeedback = async (
  params: SubmitFeedbackParams
): Promise<SubmitFeedbackResponse> => {
  const session = await getServerSession(authOptions);
  const sessionUser = session?.user as SessionUser | undefined;

  if (!session || !sessionUser?.dbId) {
    return { success: false, error: 'Unauthorized' };
  }
  const userId = sessionUser.dbId;

  const parsedBody = submitFeedbackSchema.safeParse(params);

  if (!parsedBody.success) {
    console.error('[SubmitFeedback] Invalid parameters:', parsedBody.error);
    return { success: false, error: 'Invalid parameters' };
  }

  const { quizId, is_good, userAnswer, isCorrect } = parsedBody.data;

  let feedbackSuccess = false;
  let feedbackError: string | undefined = undefined;
  try {
    const quizExists = db.prepare('SELECT id FROM quiz WHERE id = ?').get(quizId);
    if (!quizExists) {
      feedbackError = `Quiz with ID ${quizId} not found.`;
    } else {
      db.prepare(
        'INSERT INTO question_feedback (quiz_id, user_id, is_good, user_answer, is_correct) VALUES (?, ?, ?, ?, ?)'
      ).run(
        quizId,
        userId,
        is_good,
        userAnswer,
        isCorrect === undefined ? null : isCorrect ? 1 : 0
      );
      feedbackSuccess = true;
    }
  } catch (dbError) {
    console.error('[SubmitFeedback] Database error saving feedback:', dbError);
    const message = dbError instanceof Error ? dbError.message : 'Unknown DB error';
    Sentry.captureException(dbError, {
      extra: { quizId, is_good, userAnswer, isCorrect, userId },
    });
    feedbackError = `Database error saving feedback: ${message}`;
    feedbackSuccess = false;
  }

  const response: SubmitFeedbackResponse = {
    success: feedbackSuccess,
    error: feedbackError,
  };

  return response;
};
