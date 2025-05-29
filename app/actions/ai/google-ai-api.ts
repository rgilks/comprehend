import { GoogleGenAI } from '@google/genai';

let genAIClient: GoogleGenAI | null = null;

export const getGoogleAIClient = (): GoogleGenAI => {
  if (genAIClient) {
    return genAIClient;
  }

  const apiKey = process.env['GOOGLE_AI_API_KEY'];

  if (!apiKey) {
    const errorMsg =
      '[GoogleAI Client] CRITICAL: GOOGLE_AI_API_KEY environment variable is not set. Cannot initialize client.';
    console.error(errorMsg);
    throw new Error(errorMsg);
  }

  console.log('[GoogleAI Client] Initializing GoogleGenAI client...');
  try {
    genAIClient = new GoogleGenAI({ apiKey });
    return genAIClient;
  } catch (error) {
    console.error('[GoogleAI Client] Failed to initialize GoogleGenAI client:', error);
    throw error;
  }
};

export class AIResponseProcessingError extends Error {
  constructor(
    message: string,
    public readonly originalError?: unknown
  ) {
    super(message);
    this.name = 'AIResponseProcessingError';
  }
}

export const callGoogleAI = async (prompt: string): Promise<unknown> => {
  const genAI: GoogleGenAI = getGoogleAIClient();

  const generationConfig = {
    maxOutputTokens: 500,
    temperature: 0.7,
    topP: 0.9,
    topK: 40,
    frequencyPenalty: 0.3,
    presencePenalty: 0.2,
    candidateCount: 1,
    responseMimeType: 'application/json',
  };

  try {
    const modelName = process.env['GOOGLE_AI_GENERATION_MODEL'] ?? 'gemini-2.5-flash-preview-04-17';
    if (!process.env['GOOGLE_AI_GENERATION_MODEL']) {
      console.warn(
        `[AI] GOOGLE_AI_GENERATION_MODEL environment variable not set. Using default: ${modelName}`
      );
    }

    const request = {
      model: modelName,
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: generationConfig,
    };

    const result = await genAI.models.generateContent(request);

    const text: string | undefined = result.text;

    if (text === undefined) {
      console.error(
        '[AI API] Failed to extract text from Google AI response:',
        JSON.stringify(result, null, 2)
      );
      throw new AIResponseProcessingError(
        'No content received from Google AI or failed to extract text.'
      );
    }

    const jsonRegex = /```json\s*([\s\S]*?)\s*```/;
    const match = text.match(jsonRegex);
    let potentialJsonString: string;

    if (match && match[1]) {
      potentialJsonString = match[1].trim();
    } else {
      const trimmedText = text.trim();
      if (
        (trimmedText.startsWith('{') && trimmedText.endsWith('}')) ||
        (trimmedText.startsWith('[') && trimmedText.endsWith(']'))
      ) {
        potentialJsonString = trimmedText;
      } else {
        console.warn(
          '[AI API] Response received, but no JSON block found or text is not valid JSON:',
          text
        );
        throw new AIResponseProcessingError(
          'AI response received, but failed to extract valid JSON content.'
        );
      }
    }

    try {
      const parsedJson = JSON.parse(potentialJsonString);
      return parsedJson;
    } catch (parseError) {
      console.error(
        '[AI API] Failed to parse JSON from AI response string:',
        potentialJsonString,
        'Error:',
        parseError
      );
      throw new AIResponseProcessingError('Failed to parse JSON from AI response.', parseError);
    }
  } catch (error: unknown) {
    let errorMessage = 'Unknown AI generation error';
    let originalErrorForRethrow = error;

    if (error instanceof Error) {
      errorMessage = error.message;
      if (error instanceof AIResponseProcessingError) {
        originalErrorForRethrow = error.originalError ?? error;
      }
    } else {
      console.error('[AI API] Google AI API call failed with non-Error object:', error);
    }

    if (typeof errorMessage === 'string' && errorMessage.includes('SAFETY')) {
      console.warn(`[AI API] Safety setting blocked response: ${errorMessage}`);
      throw new AIResponseProcessingError(
        `Safety setting blocked response: ${errorMessage}`,
        originalErrorForRethrow
      );
    }

    console.error(
      `[AI API] AI generation failed. Message: ${errorMessage}`,
      originalErrorForRethrow
    );
    throw new AIResponseProcessingError(
      `AI generation failed: ${errorMessage}`,
      originalErrorForRethrow
    );
  }
};
