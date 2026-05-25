const API_BASE_URL = 'http://127.0.0.1:5000';

(async function silentIPCheck() {
    const SESSION_KEY = "tp_visitor_logged";
    if (sessionStorage.getItem(SESSION_KEY) === "1") return;
  
    try {
      const response = await fetch(`${API_BASE_URL}/api/get-client-info`, {
        cache: "no-store",
      });
  
      if (response.ok) {
        sessionStorage.setItem(SESSION_KEY, "1");
        console.log("✅ Visitor logged successfully in the background.");
      }
    } catch (err) {
      // Fail silently so the user never notices if the backend is off
      console.warn("⚠️ Backend offline. Visit not logged.");
    }
  })();

document.addEventListener("DOMContentLoaded", () => {
  const container = document.getElementById("container");
  const signUpBtn = document.getElementById("signUpBtn");
  const signInBtn = document.getElementById("signInBtn");

  // Function to sync UI state with URL hash
  const syncUIWithHash = () => {
    const hash = window.location.hash;
    if (!container) return;

    if (hash === "#signup") {
      container.classList.add("right-panel-active");
    } else if (hash === "#signin" || hash === "") {
      container.classList.remove("right-panel-active");
    }
  };

  // Listen for manual URL changes while the page is open
  window.addEventListener("hashchange", syncUIWithHash);

  // Process the hash immediately when the page loads
  syncUIWithHash();

  if (signUpBtn) {
    signUpBtn.addEventListener("click", () => {
      container.classList.add("right-panel-active");
      // Update URL hash to match UI state
      history.replaceState(null, null, "#signup");
    });
  }

  if (signInBtn) {
    signInBtn.addEventListener("click", () => {
      container.classList.remove("right-panel-active");
      // Update URL hash to match UI state
      history.replaceState(null, null, "#signin");
    });
  }

  if (container) {
    container.addEventListener("mousemove", (event) => {
      const rect = container.getBoundingClientRect();
      const x = ((event.clientX - rect.left) / rect.width - 0.5) * 8;
      const y = ((event.clientY - rect.top) / rect.height - 0.5) * 8;
      container.style.transform = `rotateY(${x}deg) rotateX(${-y}deg)`;
    });

    container.addEventListener("mouseleave", () => {
      container.style.transform = "rotateY(0deg) rotateX(0deg)";
    });
  }

  document.querySelectorAll(".btn-auth").forEach((button) => {
    button.addEventListener("click", (event) => {
      const ripple = document.createElement("span");
      ripple.className = "ripple";
      ripple.style.left = `${event.offsetX}px`;
      ripple.style.top = `${event.offsetY}px`;
      button.appendChild(ripple);
      setTimeout(() => ripple.remove(), 620);
    });
  });
});