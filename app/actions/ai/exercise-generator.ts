import { ExerciseContent, ExerciseContentSchema, type QuizData } from 'app/domain/schemas';
import { type ExerciseGenerationParams } from 'app/domain/ai';
import { callGoogleAI, AIResponseProcessingError } from './google-ai-api';

export { AIResponseProcessingError };

export const generateExercisePrompt = (params: ExerciseGenerationParams): string => {
  const {
    topic,
    passageLanguage,
    questionLanguage,
    passageLangName,
    questionLangName,
    level,
    grammarGuidance,
    vocabularyGuidance,
  } = params;

  const prompt = `Generate a reading comprehension exercise based on the following parameters:
- Topic: ${topic}
- Passage Language: ${passageLangName} (${passageLanguage})
- Question Language: ${questionLangName} (${questionLanguage})
- CEFR Level: ${level}
- Grammar Guidance: ${grammarGuidance}
- Vocabulary Guidance: ${vocabularyGuidance}

Instructions:
1. Create a short paragraph (3-6 sentences) in ${passageLanguage} suitable for a ${level} learner, focusing on the topic "${topic}".
2. Write ONE multiple-choice question in ${questionLanguage}. The question should target ONE of the following comprehension skills based on the paragraph: (a) main idea, (b) specific detail, (c) inference (requiring understanding information implied but not explicitly stated), OR (d) vocabulary in context (asking the meaning of a word/phrase as used in the paragraph).
3. Provide four answer options (A, B, C, D) in ${questionLanguage}. Only one option should be correct.
4. Create plausible distractors (incorrect options B, C, D): These should relate to the topic but be clearly contradicted, unsupported by the paragraph, or represent common misinterpretations based *only* on the text. Avoid options that are completely unrelated or rely on outside knowledge. **Ensure distractors are incorrect specifically because they contradict or are unsupported by the provided paragraph.**
5. **CRITICAL REQUIREMENT:** The question **must be impossible** to answer correctly *without* reading and understanding the provided paragraph. The answer **must depend solely** on the specific details or implications within the text. Avoid any questions solvable by general knowledge or common sense.
6. Identify the correct answer key (A, B, C, or D).
7. Provide **concise explanations** (in ${questionLanguage}) for **ALL options (A, B, C, D)**. For the correct answer, explain why it's right. For incorrect answers, explain specifically why they are wrong according to the text. Each explanation MUST explicitly reference the specific part of the paragraph that supports or contradicts the option.
8. Extract the specific sentence or phrase from the original paragraph (in ${passageLanguage}) that provides the primary evidence for the correct answer ("relevantText").

Output Format: Respond ONLY with a valid JSON object containing the following keys:
- "paragraph": (string) The generated paragraph in ${passageLanguage}.
- "topic": (string) The topic used: "${topic}".
- "question": (string) The multiple-choice question in ${questionLanguage}.
- "options": (object) An object with keys "A", "B", "C", "D", where each value is an answer option string in ${questionLanguage}.
- "correctAnswer": (string) The key ("A", "B", "C", or "D") of the correct answer.
- "allExplanations": (object) An object with keys "A", "B", "C", "D", where each value is the concise explanation string in ${questionLanguage} for that option, explicitly referencing the text.
- "relevantText": (string) The sentence or phrase from the paragraph in ${passageLanguage} that supports the correct answer.

Example JSON structure:
{
  "paragraph": "...",
  "topic": "...",
  "question": "...",
  "options": { "A": "...", "B": "...", "C": "...", "D": "..." },
  "correctAnswer": "B",
  "allExplanations": { "A": "Explanation A referencing text...", "B": "Explanation B referencing text...", "C": "Explanation C referencing text...", "D": "Explanation D referencing text..." },
  "relevantText": "..."
}

Ensure the entire output is a single, valid JSON object string without any surrounding text or markdown formatting.
`;
  return prompt;
};

export type ExerciseGenerationOptions = ExerciseGenerationParams & {
  language: string;
};

export const generateAndValidateExercise = async (
  options: ExerciseGenerationOptions
): Promise<ExerciseContent> => {
  const prompt = generateExercisePrompt(options);

  let aiResponse: unknown;
  try {
    aiResponse = await callGoogleAI(prompt);
  } catch (error) {
    console.error('[AI:generateAndValidateExercise] Google AI call failed:', error);
    if (error instanceof AIResponseProcessingError) {
      throw error;
    } else {
      throw new AIResponseProcessingError('AI generation call failed', error);
    }
  }

  if (typeof aiResponse !== 'object' || aiResponse === null) {
    console.error(
      '[AI:generateAndValidateExercise] AI response was not a valid object:',
      aiResponse
    );
    throw new AIResponseProcessingError(
      'AI response format is invalid (not an object).',
      aiResponse
    );
  }

  const parsedAiContent = aiResponse as Record<string, unknown>;

  try {
    const validationResult = ExerciseContentSchema.safeParse(parsedAiContent);

    if (!validationResult.success) {
      console.error(
        '[AI:generateAndValidateExercise] AI response failed Zod validation:',
        validationResult.error.format()
      );
      console.log(
        '[AI:generateAndValidateExercise] Failing AI Response Content:',
        JSON.stringify(parsedAiContent)
      );
      throw new AIResponseProcessingError(
        'AI response failed structure validation.',
        validationResult.error
      );
    }

    console.log('[AI:generateAndValidateExercise] AI response successfully parsed and validated.');
    return validationResult.data;
  } catch (error) {
    if (error instanceof AIResponseProcessingError) {
      throw error;
    }
    console.error('[AI:generateAndValidateExercise] Unexpected error during validation:', error);
    throw new AIResponseProcessingError('Unexpected validation error', error);
  }
};

export type { QuizData };
