// INTENTIONALLY VULNERABLE - test file for the SAST scanner

// XSS via innerHTML (XSS-001)
function renderComment(userInput) {
    document.getElementById("comments").innerHTML = userInput;
}

function renderName(name) {
    document.write("<h1>Hello " + name + "</h1>");
}

// Hardcoded API key - placeholders to avoid GitHub secret scanning
const API_KEY = "PLACEHOLDER_FAKE_TOKEN_XXXXXXXXXXXXXXXXXXXX";
const secret = "PLACEHOLDER_FAKE_SECRET_XXXXXXXXXXXXXXXXXXXX";

// Eval usage
function runUserCode(code) {
    return eval(code);
}
