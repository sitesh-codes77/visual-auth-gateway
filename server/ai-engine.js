const { createSentence } = require('../ai/hint-generator');

const NOISE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789@$%*?';

function randomChar() {
  return NOISE_CHARS[Math.floor(Math.random() * NOISE_CHARS.length)];
}

function buildMatrix(word, size = 5) {
  const matrix = Array.from({ length: size }, () =>
    Array.from({ length: size }, () => randomChar())
  );

  const placements = [];
  const used = new Set();

  for (const ch of word.toUpperCase()) {
    let row;
    let col;
    let key;

    do {
      row = Math.floor(Math.random() * size);
      col = Math.floor(Math.random() * size);
      key = `${row}-${col}`;
    } while (used.has(key));

    used.add(key);
    matrix[row][col] = ch;
    placements.push({ char: ch, row, col });
  }

  return {
    size,
    matrix,
    placements
  };
}

function extractPositions(sentence, word) {
  const lowerSentence = sentence.toLowerCase();
  const chars = word.toLowerCase().split('');
  const used = new Set();

  return chars.map((char) => {
    let index = -1;
    for (let i = 0; i < lowerSentence.length; i += 1) {
      if (lowerSentence[i] === char && !used.has(i)) {
        index = i;
        used.add(i);
        break;
      }
    }

    return {
      char,
      index
    };
  });
}

function generateHintBundle(originalWord, matrixSize = 5) {
  const { cleanWord, sentence } = createSentence(originalWord);
  const matrix = buildMatrix(cleanWord, matrixSize);
  const sentencePositions = extractPositions(sentence, cleanWord);

  return {
    word: cleanWord,
    sentence,
    matrixConfig: matrix,
    sentencePositions
  };
}

function buildHintLevels(bundle) {
  const highlighted = bundle.sentencePositions
    .filter((entry) => entry.index >= 0)
    .map((entry) => entry.index);

  return [1, 2, 3].map((level) => ({
    hintLevel: level,
    revealedChars: JSON.stringify(bundle.word.slice(0, level)),
    aiGeneratedSentence: bundle.sentence,
    matrixPositions: JSON.stringify(
      level < 3
        ? bundle.matrixConfig.placements.slice(0, Math.ceil(bundle.matrixConfig.placements.length / 2))
        : bundle.matrixConfig.placements
    ),
    highlighted
  }));
}

module.exports = {
  buildHintLevels,
  generateHintBundle,
  extractPositions,
  buildMatrix
};
