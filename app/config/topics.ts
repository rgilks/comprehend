type TopicCategory = {
  name: string;
  topics: string[];
};

type CEFRTopics = {
  [key: string]: TopicCategory[];
};

export const topicsByLevel: CEFRTopics = {
  A1: [
    {
      name: 'Daily Life',
      topics: [
        'Family members',
        'Daily routines',
        'Simple meals',
        'School items',
        'Basic clothing',
        'House rooms',
        'Pet animals',
        'Weather basics',
        'Colors and shapes',
        'Simple hobbies',
      ],
    },
    {
      name: 'Places',
      topics: [
        'My classroom',
        'My home',
        'The playground',
        'Local shops',
        'The park',
        'The zoo',
        'The beach',
        'Public transport',
        'School areas',
        'My neighborhood',
      ],
    },
  ],
  A2: [
    {
      name: 'Personal Experiences',
      topics: [
        'Weekend activities',
        'Simple travel',
        'Birthday parties',
        'Going shopping',
        'School subjects',
        'Sports and games',
        'Simple cooking',
        'Phone calls',
        'Making friends',
        'Describing people',
      ],
    },
    {
      name: 'Community',
      topics: [
        'Community helpers',
        'Seasonal activities',
        'Simple celebrations',
        'Going to restaurants',
        'Simple health topics',
        'City landmarks',
        'Basic directions',
        'Transport schedules',
        'School events',
        'Nature walks',
      ],
    },
  ],
  B1: [
    {
      name: 'Life Experiences',
      topics: [
        'Travel experiences',
        'Cultural differences',
        'Work and jobs',
        'Entertainment choices',
        'Personal achievements',
        'Shopping preferences',
        'Home improvements',
        'School life',
        'Food and recipes',
        'Local events',
      ],
    },
    {
      name: 'Social Topics',
      topics: [
        'Environmental issues',
        'News stories',
        'Healthy lifestyles',
        'Sports competitions',
        'Social media usage',
        'Friendship challenges',
        'Community projects',
        'Holidays abroad',
        'Personal goals',
        'Music preferences',
      ],
    },
  ],
  B2: [
    {
      name: 'Current Issues',
      topics: [
        'Technology trends',
        'Career planning',
        'Education systems',
        'Urban development',
        'Digital communication',
        'Cultural diversity',
        'Health and fitness',
        'Environmental protection',
        'Travel planning',
        'Financial basics',
      ],
    },
    {
      name: 'Deeper Perspectives',
      topics: [
        'Social changes',
        'Creative arts',
        'Personal development',
        'Modern inventions',
        'Media influence',
        'Historical events',
        'Community challenges',
        'Consumer behavior',
        'Global celebrations',
        'Work-life balance',
      ],
    },
  ],
  C1: [
    {
      name: 'Complex Issues',
      topics: [
        'Economic trends',
        'Political systems',
        'Technological advancements',
        'Environmental sustainability',
        'International relations',
        'Cultural heritage',
        'Scientific research',
        'Ethical dilemmas',
        'Media literacy',
        'Educational philosophy',
      ],
    },
    {
      name: 'Academic Topics',
      topics: [
        'Anthropological studies',
        'Philosophical debates',
        'Historical perspectives',
        'Literary analysis',
        'Healthcare systems',
        'Urban sociology',
        'Psychological theories',
        'Digital transformation',
        'Global economics',
        'Legal frameworks',
      ],
    },
  ],
  C2: [
    {
      name: 'Abstract Concepts',
      topics: [
        'Societal paradigms',
        'Cognitive science',
        'Diplomatic relations',
        'Cultural anthropology',
        'Ethical philosophies',
        'Alternative energy',
        'Linguistic evolution',
        'Post-modernism',
        'Geopolitical dynamics',
        'Identity politics',
      ],
    },
    {
      name: 'Specialized Fields',
      topics: [
        'Emerging technologies',
        'Financial markets',
        'Public policy analysis',
        'International law',
        'Comparative literature',
        'Behavioral economics',
        'Social psychology',
        'Architectural theory',
        'Media discourse analysis',
        'Scientific controversies',
      ],
    },
  ],
};

export const getTopicsForLevel = (level: string): string[] => {
  const levelTopics = topicsByLevel[level];

  if (!levelTopics) {
    return [];
  }

  return levelTopics.flatMap((category) => category.topics);
};

export const getRandomTopicForLevel = (level: string): string => {
  const topics = getTopicsForLevel(level);

  if (topics.length === 0) {
    return 'General knowledge';
  }

  const randomIndex = Math.floor(Math.random() * topics.length);
  return topics[randomIndex];
};
