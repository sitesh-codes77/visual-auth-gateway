const ADJECTIVES = [
  'amazing',
  'brilliant',
  'calm',
  'delightful',
  'elegant',
  'fresh',
  'gentle',
  'heroic',
  'intuitive',
  'joyful',
  'keen',
  'lively',
  'mindful',
  'natural',
  'optimistic',
  'playful',
  'quiet',
  'radiant',
  'steady',
  'timeless',
  'uplifting',
  'vibrant',
  'warm',
  'xenial',
  'youthful',
  'zen'
];

const NOUNS = [
  'adventures',
  'bridges',
  'clouds',
  'dreams',
  'echoes',
  'forests',
  'gardens',
  'harbors',
  'ideas',
  'journeys',
  'kites',
  'lanterns',
  'moments',
  'nights',
  'oceans',
  'paths',
  'quests',
  'rhythms',
  'stories',
  'trails',
  'uplands',
  'visions',
  'waves',
  'xylophones',
  'yards',
  'zeniths'
];

function sanitizeWord(input) {
  return (input || '').trim().replace(/[^a-zA-Z]/g, '');
}

function createSentence(word) {
  const cleanWord = sanitizeWord(word);
  if (!cleanWord || cleanWord.length < 3) {
    throw new Error('Word must contain at least 3 alphabetic characters.');
  }

  const chars = cleanWord.toLowerCase().split('');
  const words = chars.map((char, index) => {
    const bucket = index % 2 === 0 ? ADJECTIVES : NOUNS;
    const matching = bucket.filter((item) => item.startsWith(char));
    if (matching.length > 0) {
      return matching[index % matching.length];
    }
    return `${char}${bucket[index % bucket.length]}`;
  });

  const sentence = words
    .map((segment, i) => (i === 0 ? segment.charAt(0).toUpperCase() + segment.slice(1) : segment))
    .join(' ');

  return {
    cleanWord,
    sentence: `${sentence}.`
  };
}

module.exports = {
  createSentence,
  sanitizeWord
};
