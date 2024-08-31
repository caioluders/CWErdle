let cweData = [];
let dailyCWE;
let currentHintIndex = 0;
let guessesRemaining = 6;
let score = 1000;
let previousGuesses = [];

const hintList = document.getElementById('hint-list');
const guessInput = document.getElementById('guess-input');
const submitButton = document.getElementById('submit-guess');
const nextHintButton = document.getElementById('next-hint');
const resultElement = document.getElementById('result');
const guessesRemainingElement = document.getElementById('guesses-remaining');
const scoreElement = document.getElementById('score');
const autocompleteList = document.getElementById('autocomplete-list');

let cweIdToNameMap = new Map();

async function fetchAndParseCWEData() {
    try {
        const response = await fetch('cwec_v4.15.xml');
        const xmlText = await response.text();
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlText, "text/xml");
        const weaknesses = xmlDoc.getElementsByTagName("Weakness");
        
        // Create a mapping of CWE IDs to names
        Array.from(weaknesses).forEach(weakness => {
            const id = weakness.getAttribute("ID");
            const name = weakness.getAttribute("Name");
            cweIdToNameMap.set(id, name);
        });

        cweData = Array.from(weaknesses).map(weakness => ({
            id: weakness.getAttribute("ID"),
            name: weakness.getAttribute("Name"),
            description: weakness.querySelector("Description")?.textContent || "No description available",
            extendedDescription: weakness.querySelector("Extended_Description")?.textContent || "No extended description available",
            applicablePlatforms: (() => {
                const platforms = weakness.querySelector("Applicable_Platforms");
                if (!platforms) return "No platform information available";
                const languages = Array.from(platforms.querySelectorAll("Language")).map(lang => lang.getAttribute("Class"));
                const technologies = Array.from(platforms.querySelectorAll("Technology")).map(tech => tech.getAttribute("Class"));
                const allPlatforms = [...languages, ...technologies].filter(item => 
                    item && item !== "Not Language-Specific" && item.trim() !== ""
                );
                return allPlatforms.length > 0 ? allPlatforms.join(", ") : "No specific platform information available";
            })(),
            backgroundDetails: weakness.querySelector("Background_Details Background_Detail")?.textContent || "No background details available",
            demonstrativeExamples: Array.from(weakness.querySelectorAll("Demonstrative_Examples Demonstrative_Example")).map(example => {
                const introText = example.querySelector("Intro_Text")?.textContent || "";
                const bodyText = Array.from(example.querySelectorAll("Body_Text")).map(body => body.textContent).join(" ");
                return `${introText} ${bodyText}`.trim();
            }).join("\n") || "No demonstrative examples available",
            observedExamples: Array.from(weakness.querySelectorAll("Observed_Examples Observed_Example")).map(example => 
                `${example.querySelector("Reference")?.textContent}: ${example.querySelector("Description")?.textContent}`
            ).join("\n") || "No observed examples available",
            potentialMitigations: Array.from(weakness.querySelectorAll("Potential_Mitigations Mitigation")).map(mitigation => 
                `${mitigation.querySelector("Phase")?.textContent}: ${mitigation.querySelector("Description")?.textContent}`
            ).join("\n") || "No mitigation information available",
            likelihoodOfExploit: weakness.querySelector("Likelihood_Of_Exploit")?.textContent || null,
            commonConsequences: Array.from(weakness.querySelectorAll("Common_Consequences Consequence")).map(consequence => {
                const scope = consequence.querySelector("Scope")?.textContent;
                const impact = consequence.querySelector("Impact")?.textContent;
                const note = consequence.querySelector("Note")?.textContent;
                if ((scope === "Other" && impact === "Other") || (!scope && !impact)) {
                    return null; // This will be filtered out
                }
                return `Scope: ${scope || 'Not specified'}, Impact: ${impact || 'Not specified'}${note ? `, Note: ${note}` : ''}`;
            }).filter(Boolean).join("\n") || "No common consequences available",
            relatedWeaknesses: Array.from(weakness.querySelectorAll("Related_Weaknesses Related_Weakness"))
                .map(related => related.getAttribute("CWE_ID"))
                .filter(Boolean) // Remove any undefined or null values
                .join("\n") || "No related weaknesses available",
        }));
        
        console.log(`Loaded ${cweData.length} CWEs`);
        initializeGame(); // This will now call startNewGame
    } catch (error) {
        console.error('Error fetching or parsing CWE data:', error);
        resultElement.textContent = 'Error loading CWE data. Please refresh the page.';
    }
}

function getRandomCWE(seed_override = null) {
    // Get the current date and format it as YYYYMMDD
    const today = new Date();
    const dateString = today.getFullYear().toString() +
                       (today.getMonth() + 1).toString().padStart(2, '0') +
                       today.getDate().toString().padStart(2, '0');
    
    // Use the date string to seed the random number generator
    let seed = 0;
    for (let i = 0; i < dateString.length; i++) {
        seed = ((seed << 5) - seed + dateString.charCodeAt(i)) | 0;
    }
    
    if (seed_override !== null) {
        seed = seed_override;
    }

    // Use the seeded random number to select a non-deprecated CWE
    let attempts = 0;
    const maxAttempts = cweData.length; // Prevent infinite loop
    while (attempts < maxAttempts) {
        const randomIndex = Math.abs(seed) % cweData.length;
        const selectedCWE = cweData[randomIndex];
        
        if (!selectedCWE.name.toUpperCase().includes('DEPRECATED')) {
            return selectedCWE;
        }
        
        // If the selected CWE is deprecated, generate a new seed
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        attempts++;
    }
    
    // If we've tried all CWEs and they're all deprecated (unlikely), return null
    console.error('All CWEs appear to be deprecated');
    return null;
}

function generateHints(cwe) {
    let hints = [];

    if (cwe.applicablePlatforms && 
        cwe.applicablePlatforms !== "No specific platform information available" && 
        cwe.applicablePlatforms !== "No platform information available") {
        const platforms = cwe.applicablePlatforms.split(',').map(p => p.trim()).filter(p => p);
        if (platforms.length > 0) {
            hints.push(`Applicable Platforms: ${platforms.join(', ')}`);
        }
    }

    if (cwe.observedExamples && cwe.observedExamples !== "No observed examples available") {
        hints.push(`Observed Examples:\n${cwe.observedExamples}`);
    }

    if (cwe.potentialMitigations && cwe.potentialMitigations !== "No mitigation information available") {
        hints.push(`Potential Mitigations:\n${cwe.potentialMitigations}`);
    }

    if (cwe.backgroundDetails && cwe.backgroundDetails !== "No background details available") {
        hints.push(`Background Details: ${cwe.backgroundDetails}`);
    }

    if (cwe.demonstrativeExamples && cwe.demonstrativeExamples !== "No demonstrative examples available") {
        hints.push(`Demonstrative Examples:\n${cwe.demonstrativeExamples}`);
    }

    if (cwe.extendedDescription && cwe.extendedDescription !== "No extended description available") {
        hints.push(`Extended Description: ${cwe.extendedDescription}`);
    }

    if (cwe.likelihoodOfExploit) {
        hints.push(`Likelihood of Exploit: ${cwe.likelihoodOfExploit}`);
    }

    if (cwe.commonConsequences && cwe.commonConsequences !== "No common consequences available") {
        hints.push(`Common Consequences:\n${cwe.commonConsequences}`);
    }

    if (cwe.relatedWeaknesses && cwe.relatedWeaknesses !== "No related weaknesses available") {
        const relatedWeaknessesHints = cwe.relatedWeaknesses.split('\n').map(relatedId => {
            const relatedName = cweIdToNameMap.get(relatedId) || "Unknown";
            return `CWE-${relatedId}: ${relatedName}`;
        }).join('\n');
        hints.push(`Related Weaknesses:\n${relatedWeaknessesHints}`);
    }

    // Always include the description as the last hint
    hints.push(`Description: ${cwe.description}`);

    return hints;
}

function initializeGame() {
    const newCWE = getRandomCWE();
    if (newCWE) {
        dailyCWE = newCWE;
        previousGuesses = []; // Reset previous guesses
        updatePreviousGuessesList(); // Update the display
        startNewGame(false);
    } else {
        resultElement.textContent = 'Error: Unable to find a non-deprecated CWE. Please refresh the page.';
    }
}

function getCWESuggestions(query) {
    query = query.toLowerCase();
    return cweData
        .filter(cwe => 
            `cwe-${cwe.id}`.toLowerCase().includes(query) || 
            cwe.name.toLowerCase().includes(query)
        )
        .slice(0, 10);
}

function updateCWESuggestions(suggestions) {
    autocompleteList.innerHTML = '';
    suggestions.forEach(suggestion => {
        const div = document.createElement('div');
        div.innerHTML = `<strong>CWE-${suggestion.id}</strong>: ${suggestion.name}`;
        div.addEventListener('click', function() {
            guessInput.value = `CWE-${suggestion.id}`;
            autocompleteList.innerHTML = '';
        });
        autocompleteList.appendChild(div);
    });
}

function initializeHintList() {
    hintList.innerHTML = '';
    dailyCWE.hints.forEach((hint, index) => {
        const hintItem = document.createElement('li');
        hintItem.className = 'hint-item' + (index === 0 ? ' revealed' : ' hidden');
        hintItem.id = `hint-${index}`;
        
        if (index === 0) {
            hintItem.textContent = hint;
        } else {
            hintItem.textContent = `Hint ${index + 1}`;
        }
        
        hintList.appendChild(hintItem);
    });
}

function updateHint() {
    const currentHintItem = document.getElementById(`hint-${currentHintIndex}`);
    currentHintItem.classList.remove('hidden');
    currentHintItem.classList.add('revealed');
}

function updateGameInfo() {
    guessesRemainingElement.textContent = guessesRemaining;
    scoreElement.textContent = score;
}

function revealNextHint() {
    if (currentHintIndex < dailyCWE.hints.length - 1) {
        currentHintIndex++;
        const newHintItem = document.getElementById(`hint-${currentHintIndex}`);
        newHintItem.classList.remove('hidden');
        newHintItem.classList.add('revealed', 'new-hint');
        newHintItem.textContent = dailyCWE.hints[currentHintIndex];
        setTimeout(() => newHintItem.classList.remove('new-hint'), 500);
        score -= 100;
        updateGameInfo();
    } else {
        nextHintButton.disabled = true;
        resultElement.textContent = "No more hints available.";
    }
}

function checkGuess() {
    const guess = guessInput.value.trim().toUpperCase();
    const correctAnswer = `CWE-${dailyCWE.id}`;
    
    // Add the guess to previousGuesses array only if it's not already there
    if (!previousGuesses.includes(guess)) {
        previousGuesses.push(guess);
        updatePreviousGuessesList();
    }

    if (guess === correctAnswer || guess === dailyCWE.name.toUpperCase()) {
        endGame(true);
    } else {
        guessesRemaining--;
        updateScore(false);
        updateGameInfo();

        // Add incorrect animation to revealed hints
        document.querySelectorAll('.hint-item.revealed').forEach(hint => {
            hint.classList.add('incorrect');
            setTimeout(() => hint.classList.remove('incorrect'), 820);
        });

        if (guessesRemaining <= 0) {
            endGame(false);
        } else {
            resultElement.textContent = "Incorrect guess. Try again!";
            revealNextHint();
        }
    }
    guessInput.value = '';
    autocompleteList.innerHTML = '';
}

function endGame(won) {
    submitButton.disabled = true;
    nextHintButton.disabled = true;

    if (won) {
        resultElement.textContent = "Congratulations! You guessed correctly!";
        updateScore(true);
        
        // Add correct animation to all revealed hints
        document.querySelectorAll('.hint-item.revealed').forEach(hint => {
            hint.classList.add('correct');
        });

        // Remove the correct animation after 3 seconds
        setTimeout(() => {
            document.querySelectorAll('.hint-item.correct').forEach(hint => {
                hint.classList.remove('correct');
            });
        }, 3000);
    } else {
        resultElement.textContent = `Game over! The correct answer was CWE-${dailyCWE.id}: ${dailyCWE.name}.`;
        // Reveal all hints
        dailyCWE.hints.forEach((hint, index) => {
            const hintItem = document.getElementById(`hint-${index}`);
            hintItem.classList.remove('hidden');
            hintItem.classList.add('revealed');
            hintItem.textContent = hint;
        });
    }
    
    // Add buttons for new game and sharing
    const buttonContainer = document.createElement('div');
    buttonContainer.className = 'mt-3';
    
    const newGameButton = document.createElement('button');
    newGameButton.textContent = "Play Another CWE";
    newGameButton.className = "btn btn-primary me-2";
    newGameButton.addEventListener('click', () => startNewGame(true));
    
    const twitterButton = document.createElement('button');
    twitterButton.textContent = "Share on Twitter";
    twitterButton.className = "btn btn-info";
    twitterButton.addEventListener('click', shareOnTwitter);
    
    buttonContainer.appendChild(newGameButton);
    buttonContainer.appendChild(twitterButton);
    
    resultElement.appendChild(document.createElement('br'));
    resultElement.appendChild(buttonContainer);

    // Disable the guess input
    guessInput.disabled = true;
}

function startNewGame(newDay = false) {
    // Reset game state
    currentHintIndex = 0;
    guessesRemaining = 6;
    
    // Get a new CWE only if it's a new day
    if (newDay) {
        dailyCWE = getRandomCWE(Math.floor(Math.random() * 1000000));
    } else {
        dailyCWE = getRandomCWE();
    }
    console.log('New game started with CWE:', dailyCWE); // Log the CWE for debugging
    
    // Generate new hints
    dailyCWE.hints = generateHints(dailyCWE);
    
    // Reset UI
    initializeHintList();
    updateHint();
    updateGameInfo();
    resultElement.textContent = '';
    submitButton.disabled = false;
    nextHintButton.disabled = false;
    
    // Clear the guess input
    guessInput.value = '';
    
    // Clear the autocomplete list
    autocompleteList.innerHTML = '';
    
    // Reset previous guesses
    previousGuesses = [];
    updatePreviousGuessesList();

    // Enable the guess input
    guessInput.disabled = false;
}

function updateScore(correct) {
    if (correct) {
        score += 500; // Add points for correct guess
    } else {
        score = Math.max(0, score - 100); // Deduct points for incorrect guess, but don't go below 0
    }
    scoreElement.textContent = score;
}

function shareOnTwitter() {
    const hintsUsed = currentHintIndex + 1;
    const maxHints = dailyCWE.hints.length;
    const date = new Date().toISOString().split('T')[0];
    const tweetText = `I solved CWErdle for ${date}! 🎉\nCWE-${dailyCWE.id}: ${dailyCWE.name}\nHints used: ${hintsUsed}/${maxHints}\nScore: ${score}\nCan you beat my score? Play at ${document.location.href}`;
    const encodedTweet = encodeURIComponent(tweetText);
    window.open(`https://twitter.com/intent/tweet?text=${encodedTweet}`, '_blank');
}

function updatePreviousGuessesList() {
    const guessList = document.getElementById('guess-list');
    guessList.innerHTML = '';
    previousGuesses.forEach((guess, index) => {
        const listItem = document.createElement('li');
        listItem.className = 'list-group-item';
        listItem.textContent = `${index + 1}. ${guess}`;
        guessList.appendChild(listItem);
    });
}

submitButton.addEventListener('click', checkGuess);
nextHintButton.addEventListener('click', revealNextHint);

guessInput.addEventListener('input', (e) => {
    const query = e.target.value;
    if (query.length >= 2) {  // Changed from 3 to 2 for earlier suggestions
        const suggestions = getCWESuggestions(query);
        updateCWESuggestions(suggestions);
    } else {
        autocompleteList.innerHTML = '';
    }
});

document.addEventListener("click", function (e) {
    if (e.target !== guessInput && e.target !== autocompleteList) {
        autocompleteList.innerHTML = '';
    }
});

// Initialize the game
fetchAndParseCWEData();