'use server';

import { getServerSession } from 'next-auth';
import { headers } from 'next/headers';
import { authOptions } from 'app/features/auth/authOptions';
import { findUserIdByProvider } from 'app/repo/userRepo';
import {
  ExerciseRequestParamsSchema,
  type GenerateExerciseResult,
  type ExerciseRequestParams,
  type ExerciseContent,
  PartialQuizDataSchema,
  type InitialExercisePairResult,
  GenerateExerciseResultSchema,
  QuizDataSchema,
  type PartialQuizData,
} from 'app/domain/schemas';
import {
  generateAndValidateExercise,
  type ExerciseGenerationOptions,
} from 'app/actions/ai/exercise-generator';
import { type ExerciseGenerationParams } from 'app/domain/ai';
import { type Result, type ActionError, success, failure } from 'app/utils/result-types';
import { extractZodErrors } from 'app/utils/errorUtils';
import { getGrammarGuidance, getVocabularyGuidance } from 'app/domain/language-guidance';
import { LANGUAGES } from 'app/domain/language';
import {
  getRateLimit,
  incrementRateLimit,
  resetRateLimit,
  createRateLimit,
} from 'app/repo/rateLimitRepo';
import {
  getCachedExerciseToAttempt as getCachedExercise,
  saveExercise as saveExerciseToCache,
  countCachedExercisesInRepo as countCachedExercises,
  type QuizRow,
} from 'app/repo/quizRepo';
import { z } from 'zod';
// import { extractZodErrors } from 'app/lib/utils/errorUtils'; // This line is a duplicate and points to an old path, removing

const getDbUserIdFromSession = (
  session: { user: { id?: string | null; provider?: string | null } } | null
): number | null => {
  if (!session || !session.user.id || !session.user.provider) {
    if (session) {
      console.warn(
        `[getDbUserIdFromSession] Cannot perform direct lookup: Missing session.user.id (${session.user.id}) or session.user.provider (${session.user.provider})`
      );
    }
    return null;
  }

  try {
    const userId = findUserIdByProvider(session.user.id, session.user.provider);
    if (userId === undefined) {
      console.warn(
        `[getDbUserIdFromSession] Direct lookup failed: Could not find user for providerId: ${session.user.id}, provider: ${session.user.provider}`
      );
      return null;
    }
    return userId;
  } catch (dbError) {
    console.error('[getDbUserIdFromSession] Direct lookup DB error:', dbError);
    return null;
  }
};

const getValidatedExerciseFromCache = (
  passageLanguage: string,
  questionLanguage: string,
  level: string,
  userId: number | null
): { quizData: PartialQuizData; quizId: number } | undefined => {
  const cachedExercise: QuizRow | undefined = getCachedExercise(
    passageLanguage,
    questionLanguage,
    level,
    userId
  );

  if (cachedExercise) {
    try {
      const parsedCachedContent: unknown = JSON.parse(cachedExercise.content);
      const validatedCachedData = QuizDataSchema.safeParse(parsedCachedContent);

      if (!validatedCachedData.success) {
        console.error(
          '[Action:getValidated] Invalid data found in cache for ID',
          cachedExercise.id,
          ':',
          validatedCachedData.error.format()
        );
        return undefined;
      } else {
        const fullData = validatedCachedData.data;
        const partialData: PartialQuizData = {
          paragraph: fullData.paragraph,
          question: fullData.question,
          options: fullData.options,
          topic: fullData.topic,
        };
        return {
          quizData: partialData,
          quizId: cachedExercise.id,
        };
      }
    } catch (error) {
      console.error(
        '[Action:getValidated] Error processing cached exercise ID',
        cachedExercise.id,
        ':',
        error
      );
      return undefined;
    }
  }

  return undefined;
};

const MAX_REQUESTS_PER_HOUR = parseInt(
  process.env['RATE_LIMIT_MAX_REQUESTS_PER_HOUR'] || '100',
  10
);
const RATE_LIMIT_WINDOW = parseInt(process.env['RATE_LIMIT_WINDOW_MS'] || '3600000', 10);

const checkRateLimit = (ip: string): boolean => {
  try {
    const now = Date.now();
    const rateLimitRow = getRateLimit(ip);

    if (!rateLimitRow) {
      createRateLimit(ip, new Date(now).toISOString());
      return true;
    }

    const windowStartTime = new Date(rateLimitRow.window_start_time).getTime();
    const isWithinWindow = now - windowStartTime < RATE_LIMIT_WINDOW;

    if (isWithinWindow) {
      if (rateLimitRow.request_count >= MAX_REQUESTS_PER_HOUR) {
        return false;
      }
      incrementRateLimit(ip);
      return true;
    }

    resetRateLimit(ip, new Date(now).toISOString());
    return true;
  } catch (error) {
    console.error('[RateLimiter] Error checking rate limit:', error);
    return false;
  }
};

const DEFAULT_ERROR_PARTIAL_QUIZ_DATA: PartialQuizData = {
  paragraph: '',
  question: '',
  options: { A: '', B: '', C: '', D: '' },
  topic: '',
};

const createErrorResponse = (error: string, details?: unknown): GenerateExerciseResult => ({
  quizData: DEFAULT_ERROR_PARTIAL_QUIZ_DATA,
  quizId: -1,
  error: `${error}${details ? `: ${JSON.stringify(details)}` : ''}`,
  cached: false,
});

const CACHE_GENERATION_THRESHOLD = 100;

const createSuccessResult = (
  data: { content: ExerciseContent; id: number },
  cached: boolean = false
): GenerateExerciseResult => {
  const partialData = PartialQuizDataSchema.parse({
    paragraph: data.content.paragraph,
    question: data.content.question,
    options: data.content.options,
    topic: data.content.topic,
  });
  return {
    quizData: partialData,
    quizId: data.id,
    error: null,
    cached,
  };
};

const tryGenerateAndCacheExercise = async (
  params: ExerciseGenerationParams,
  userId: number | null
): Promise<Result<{ content: ExerciseContent; id: number }, ActionError>> => {
  try {
    const options: ExerciseGenerationOptions = { ...params, language: params.passageLanguage };
    const generatedExercise = await generateAndValidateExercise(options);
    const exerciseId = saveExerciseToCache(
      params.passageLanguage,
      params.questionLanguage,
      params.level,
      JSON.stringify(generatedExercise),
      userId
    );
    if (typeof exerciseId !== 'number') {
      return failure({ error: 'Exercise generated but failed to save to cache (undefined ID).' });
    }
    return success({ content: generatedExercise, id: exerciseId });
  } catch (error) {
    return failure({
      error: `Error during AI generation/processing: ${error instanceof Error ? error.message : String(error)}`,
    });
  }
};

const getOrGenerateExercise = async (
  genParams: ExerciseGenerationParams,
  userId: number | null,
  cachedCount: number
): Promise<GenerateExerciseResult> => {
  const requestParams: ExerciseRequestParams = {
    passageLanguage: genParams.passageLanguage,
    questionLanguage: genParams.questionLanguage,
    cefrLevel: genParams.level,
  };

  const attemptGeneration = () => tryGenerateAndCacheExercise(genParams, userId);

  const preferGenerate = cachedCount < CACHE_GENERATION_THRESHOLD;
  let generationError: ActionError | null = null;

  if (preferGenerate) {
    const genResult = await attemptGeneration();
    if (genResult.success) {
      return createSuccessResult(genResult.data, false);
    }
    generationError = genResult.error;

    const validatedCacheResultPreferGen = getValidatedExerciseFromCache(
      requestParams.passageLanguage,
      requestParams.questionLanguage,
      requestParams.cefrLevel,
      userId
    );
    if (validatedCacheResultPreferGen) {
      return {
        quizData: validatedCacheResultPreferGen.quizData,
        quizId: validatedCacheResultPreferGen.quizId,
        cached: true,
        error: null,
      };
    }
    return createErrorResponse(
      generationError.error || 'Generation preferred but failed, and no cached version available.'
    );
  }

  const validatedCacheResultOtherwise = getValidatedExerciseFromCache(
    requestParams.passageLanguage,
    requestParams.questionLanguage,
    requestParams.cefrLevel,
    userId
  );
  if (validatedCacheResultOtherwise) {
    return {
      quizData: validatedCacheResultOtherwise.quizData,
      quizId: validatedCacheResultOtherwise.quizId,
      cached: true,
      error: null,
    };
  }

  const genResult = await attemptGeneration();
  if (genResult.success) {
    return createSuccessResult(genResult.data, false);
  }
  return createErrorResponse(
    genResult.error.error || 'Cache miss and subsequent generation failed.'
  );
};

const getRequestContext = async () => {
  const headersList = await headers();
  const ip = headersList.get('x-forwarded-for') || 'unknown';
  const session = await getServerSession(authOptions);
  const userId = getDbUserIdFromSession(session);
  return { ip, userId };
};

const validateAndExtractParams = (requestParams: unknown) => {
  const validationResult = ExerciseRequestParamsSchema.safeParse(requestParams);
  if (!validationResult.success) {
    return {
      validParams: null,
      errorMsg: `Invalid request parameters: ${extractZodErrors(validationResult.error)}`,
    };
  }
  return { validParams: validationResult.data, errorMsg: null };
};

const buildGenParams = (
  validParams: ExerciseRequestParams,
  topic?: string
): ExerciseGenerationParams => ({
  passageLanguage: validParams.passageLanguage,
  questionLanguage: validParams.questionLanguage,
  level: validParams.cefrLevel,
  passageLangName: LANGUAGES[validParams.passageLanguage],
  questionLangName: LANGUAGES[validParams.questionLanguage],
  topic: topic || getRandomTopicForLevel(validParams.cefrLevel),
  grammarGuidance: getGrammarGuidance(validParams.cefrLevel),
  vocabularyGuidance: getVocabularyGuidance(validParams.cefrLevel),
});

export const generateExerciseResponse = async (
  requestParams: unknown
): Promise<GenerateExerciseResult> => {
  const { ip, userId } = await getRequestContext();
  const { validParams, errorMsg } = validateAndExtractParams(requestParams);
  if (!validParams) return createErrorResponse(errorMsg);

  if (!checkRateLimit(ip)) {
    const validatedCacheResultRateLimit = getValidatedExerciseFromCache(
      validParams.passageLanguage,
      validParams.questionLanguage,
      validParams.cefrLevel,
      userId
    );
    if (validatedCacheResultRateLimit) {
      return {
        quizData: validatedCacheResultRateLimit.quizData,
        quizId: validatedCacheResultRateLimit.quizId,
        cached: true,
        error: null,
      };
    }
    return createErrorResponse('Rate limit exceeded and no cached question available.');
  }

  const genParams = buildGenParams(validParams);
  const cachedCountValue = countCachedExercises(
    genParams.passageLanguage,
    genParams.questionLanguage,
    genParams.level
  );

  try {
    return await getOrGenerateExercise(genParams, userId, cachedCountValue);
  } catch (error) {
    console.error('Error in generateExerciseResponse:', error);
    return createErrorResponse(
      error instanceof Error ? error.message : 'Unknown error during exercise generation process'
    );
  }
};

export const generateInitialExercisePair = async (
  requestParams: unknown
): Promise<InitialExercisePairResult> => {
  const { ip, userId } = await getRequestContext();
  const { validParams, errorMsg } = validateAndExtractParams(requestParams);
  if (!validParams) return { quizzes: [], error: errorMsg };

  if (!checkRateLimit(ip)) return { quizzes: [], error: 'Rate limit exceeded.' };

  const genParams1 = buildGenParams(validParams);
  const genParams2 = buildGenParams(validParams, getRandomTopicForLevel(validParams.cefrLevel));

  try {
    const [res1, res2] = await Promise.all([
      getOrGenerateExercise(genParams1, userId, 0),
      getOrGenerateExercise(genParams2, userId, 0),
    ]);

    const errors = [res1, res2].map((r) => r.error).filter(Boolean);
    if (errors.length > 0) {
      return { quizzes: [], error: `Failed to generate exercise pair: ${errors.join('; ')}` };
    }

    const validatedResults = z.array(GenerateExerciseResultSchema).safeParse([res1, res2]);
    if (validatedResults.success) {
      return {
        quizzes: validatedResults.data as [GenerateExerciseResult, GenerateExerciseResult],
        error: null,
      };
    }
    return {
      quizzes: [],
      error: 'Internal error processing generated results after successful generation.',
    };
  } catch (error) {
    console.error('Error in generateInitialExercisePair:', error);
    const message = error instanceof Error ? error.message : 'Unknown generation error';
    return { quizzes: [], error: `Server error during generation: ${message}` };
  }
};
