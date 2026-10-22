document.addEventListener("DOMContentLoaded", function () {

    updateNavbar();

    if (document.getElementById("resultContent")) {
        loadResult();
    }

    if (document.getElementById("historyList")) {
        renderHistory();
    }

});


// =========================================================
// NAVBAR
// =========================================================

async function updateNavbar() {

    const loginNav = document.getElementById("loginNav");
    const logoutNav = document.getElementById("logoutNav");

    if (!loginNav || !logoutNav) {
        return;
    }

    try {

        const response = await fetch("/api/session");
        const data = await response.json();

        if (data.loggedIn) {
            loginNav.style.display = "none";
            logoutNav.style.display = "block";
        } else {
            loginNav.style.display = "block";
            logoutNav.style.display = "none";
        }

    } catch (error) {

        console.error("Session check failed:", error);

        loginNav.style.display = "block";
        logoutNav.style.display = "none";
    }
}


// =========================================================
// REGISTER
// =========================================================

async function register() {

    const name = document.getElementById("registerName").value.trim();
    const email = document.getElementById("registerEmail").value.trim();
    const password = document.getElementById("registerPassword").value;

    if (!name || !email || !password) {
        alert("Please fill all fields.");
        return;
    }

    try {

        const response = await fetch("/api/register", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                name: name,
                email: email,
                password: password
            })

        });

        const data = await response.json();

        if (data.success) {

            alert(data.message);

            window.location.href = "login.html";

        } else {

            alert(data.message);
        }

    } catch (error) {

        console.error("Registration error:", error);

        alert("Unable to connect to server.");
    }
}


// =========================================================
// LOGIN
// =========================================================

async function login() {

    const email = document.getElementById("loginEmail").value.trim();
    const password = document.getElementById("loginPassword").value;

    if (!email || !password) {

        alert("Please enter email and password.");

        return;
    }

    try {

        const response = await fetch("/api/login", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                email: email,
                password: password
            })

        });

        const data = await response.json();

        if (data.success) {

            alert(data.message);

            window.location.href = "scanner.html";

        } else {

            alert(data.message);
        }

    } catch (error) {

        console.error("Login error:", error);

        alert("Unable to connect to server.");
    }
}


// =========================================================
// LOGOUT
// =========================================================

async function logout() {

    try {

        const response = await fetch("/api/logout", {
            method: "POST"
        });

        const data = await response.json();

        if (data.success) {

            alert(data.message);

            window.location.href = "index.html";

        } else {

            alert(data.message);
        }

    } catch (error) {

        console.error("Logout error:", error);

        alert("Unable to logout.");
    }
}


// =========================================================
// EXAMPLE URL
// =========================================================

function example(url) {

    const input = document.getElementById("urlInput");

    if (input) {
        input.value = url;
    }
}


// =========================================================
// SCAN URL
// =========================================================

async function scanURL() {

    const input = document.getElementById("urlInput");

    if (!input) {
        return;
    }

    const url = input.value.trim();

    if (!url) {

        alert("Please enter a URL.");

        return;
    }

    try {

        const response = await fetch("/api/scan", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });

        const data = await response.json();

        if (data.success) {

            /*
             * Store only the latest result temporarily
             * so result.html can display it immediately.
             *
             * The actual scan is already stored in MySQL.
             */

            localStorage.setItem(
                "linkShieldCurrentResult",
                JSON.stringify(data.result)
            );

            window.location.href = "result.html";

        } else {

            alert(data.message);
        }

    } catch (error) {

        console.error("Scan error:", error);

        alert("Unable to connect to server.");
    }
}


// =========================================================
// LOAD LATEST RESULT
// =========================================================

async function loadResult() {

    const container = document.getElementById("resultContent");

    if (!container) {
        return;
    }

    try {

        const params = new URLSearchParams(window.location.search);
const scanId = params.get("scan");

const response = scanId
    ? await fetch(`/api/history/${encodeURIComponent(scanId)}`)
    : await fetch("/api/scan/latest");

        const data = await response.json();

        if (!data.success) {

            container.innerHTML = `
                <div class="result-box">

                    <div class="result-status danger">

                        <div class="result-icon">⚠️</div>

                        <h2>${escapeHTML(data.message || "Unable to load result")}</h2>

                    </div>

                </div>
            `;

            return;
        }

        if (!data.result) {

            container.innerHTML = `
                <div class="result-box">

                    <div class="result-status danger">

                        <div class="result-icon">⚠️</div>

                        <h2>No Scan Result Found</h2>

                        <p>Please scan a URL first.</p>

                    </div>

                </div>
            `;

            return;
        }

        /*
         * Save latest result locally only for convenience.
         * Database remains the actual source of truth.
         */

        localStorage.setItem(
            "linkShieldCurrentResult",
            JSON.stringify(data.result)
        );

        showResult(data.result);

    } catch (error) {

        console.error("Load result error:", error);

        /*
         * If the API fails, try displaying the temporarily
         * stored result.
         */

        const savedResult = localStorage.getItem(
            "linkShieldCurrentResult"
        );

        if (savedResult) {

            try {

                const result = JSON.parse(savedResult);

                showResult(result);

                return;

            } catch (parseError) {

                console.error(
                    "Saved result parsing error:",
                    parseError
                );
            }
        }

        container.innerHTML = `
            <div class="result-box">

                <div class="result-status danger">

                    <div class="result-icon">⚠️</div>

                    <h2>Unable to Load Result</h2>

                    <p>Please make sure the Flask server is running.</p>

                </div>

            </div>
        `;
    }
}


// =========================================================
// SHOW RESULT
// =========================================================

function showResult(result) {

    const container = document.getElementById("resultContent");

    if (!container) {
        return;
    }

    /*
     * Flask returns both "safe" and "is_safe".
     * Use "safe" first and fall back to "is_safe".
     */

    const safe = result.safe !== undefined
        ? Boolean(result.safe)
        : Boolean(result.is_safe);

    const prediction = result.prediction || (
        safe ? "Legitimate" : "Phishing"
    );

    const riskScore = result.risk_score !== undefined &&
                      result.risk_score !== null
        ? Number(result.risk_score)
        : null;

    const reasons = Array.isArray(result.reasons)
        ? result.reasons
        : [];


    container.innerHTML = `

        <div class="result-box">

            <div class="result-status ${safe ? "safe" : "danger"}">

                <div class="result-icon">
                    ${safe ? "✅" : "⚠️"}
                </div>

                <h2>
                    ${safe
                        ? "URL Appears Safe"
                        : "Potential Threat Detected"
                    }
                </h2>

                <p>
                    ${safe
                        ? "No obvious phishing indicators were detected."
                        : "This URL contains suspicious characteristics."
                    }
                </p>

                <div class="result-url">
                    ${escapeHTML(result.url)}
                </div>

            </div>


            <div class="result-details">

                <h3>Security Checks</h3>

                ${
                    reasons.length > 0
                        ? reasons.map(function (reason) {

                            return `

                                <div class="check">

                                    <span>
                                        ${escapeHTML(reason)}
                                    </span>

                                    <span class="${safe ? "pass" : "warning"}">

                                        ${safe ? "PASS" : "WARNING"}

                                    </span>

                                </div>

                            `;

                        }).join("")
                        : `
                            <div class="check">

                                <span>
                                    No security checks available.
                                </span>

                            </div>
                        `
                }


                <div class="check">

                    <span>
                        Prediction
                    </span>

                    <span class="${safe ? "pass" : "warning"}">

                        ${escapeHTML(prediction)}

                    </span>

                </div>


                ${
                    riskScore !== null
                        ? `

                            <div class="check">

                                <span>
                                    Risk Score
                                </span>

                                <span class="${riskScore < 50 ? "pass" : "warning"}">

                                    ${riskScore.toFixed(2)}%

                                </span>

                            </div>

                          `
                        : ""
                }

            </div>

        </div>

    `;
}


// =========================================================
// RENDER HISTORY
// =========================================================

async function renderHistory() {

    const container = document.getElementById("historyList");

    if (!container) {
        return;
    }

    try {

        const response = await fetch("/api/history");
        const data = await response.json();

        if (!data.success) {

            container.innerHTML = `
                <div class="empty-history">
                    <div>⚠️</div>
                    <h3>${escapeHTML(data.message || "Unable to load history")}</h3>
                </div>
            `;

            return;
        }

        const history = Array.isArray(data.history)
            ? data.history
            : [];

        if (history.length === 0) {

            container.innerHTML = `
                <div class="empty-history">
                    <div>📋</div>
                    <h3>No scan history</h3>
                    <p>Your scanned URLs will appear here.</p>
                </div>
            `;

            return;
        }

        container.innerHTML = history.map(function (item) {

            const safe = item.safe !== undefined
                ? Boolean(item.safe)
                : Boolean(item.is_safe);

            return `
                <div class="history-item"
                     onclick="viewHistoryResult(${Number(item.id)})">

                    <div class="history-info">

                        <div class="history-url">
                            ${escapeHTML(item.url)}
                        </div>

                        <div class="history-date">
                            Scanned: ${escapeHTML(item.date || "")}
                        </div>

                    </div>

                    <div class="history-status">
                        <span class="${safe ? "safe-label" : "danger-label"}">
                            ${safe ? "✓ SAFE" : "⚠ THREAT"}
                        </span>
                    </div>

                </div>
            `;

        }).join("");

    } catch (error) {

        console.error("History error:", error);

        container.innerHTML = `
            <div class="empty-history">
                <div>⚠️</div>
                <h3>Unable to load scan history</h3>
                <p>Please make sure the Flask server is running.</p>
            </div>
        `;
    }
}

// =========================================================
// CLEAR HISTORY
// =========================================================

async function clearHistory() {

    if (!confirm("Clear all scan history?")) {
        return;
    }

    try {

        const response = await fetch("/api/history", {

            method: "DELETE"

        });

        const data = await response.json();

        if (data.success) {

            alert(data.message);

            /*
             * Clear temporary latest-result storage as well.
             */

            localStorage.removeItem("linkShieldCurrentResult");

            renderHistory();

        } else {

            alert(data.message);
        }

    } catch (error) {

        console.error("Clear history error:", error);

        alert("Unable to connect to server.");
    }
}


// =========================================================
// ESCAPE HTML
// =========================================================

function escapeHTML(value) {

    return String(value)

        .replace(/&/g, "&amp;")

        .replace(/</g, "&lt;")

        .replace(/>/g, "&gt;")

        .replace(/"/g, "&quot;")

        .replace(/'/g, "&#039;");
}



// =========================================================
// VIEW HISTORY RESULT
// =========================================================

function viewHistoryResult(scanId) {

    if (!scanId) {
        alert("Invalid scan ID.");
        return;
    }

    window.location.href =
        `result.html?scan=${encodeURIComponent(scanId)}`;
}