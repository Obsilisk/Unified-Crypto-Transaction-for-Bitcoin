function openTab(event, tabName) {
  var i, tabcontent;

  // Hide all tab content
  tabcontent = document.getElementsByClassName("tab");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
  }

  // Show the current tab
  document.getElementById(tabName).style.display = "block";
}

function openCamera() {
  document.getElementById("cameraContainer").style.display = "block";
  openTab(event, "scan");
  // Start the scanning process
  startScanning();
}

function startScanning() {
  document.getElementById("cameraContainer").innerHTML =
    "<p>Scanning... Please wait...</p>";

  // Fetch the QR code scanning
  fetch("/scan_qr")
    .then((response) => {
      if (!response.ok) {
        throw new Error("QR Code scan failed");
      }
      return response.json();
    })
    .then((data) => {
      if (data.status === "success") {
        handleDetectedAddress(data.address); // Autofill address
        document.getElementById("receiver_address_scan").value = data.address; // Autofill the address input
      } else {
        alert(data.message); // Alert if no QR code is found
      }
    })
    .catch((error) => {
      console.error("Error:", error);
      alert("Error scanning QR code. Please try again.");
    })
    .finally(() => {
      // Clear the loading message once done
      document.getElementById("cameraContainer").innerHTML = "";
    });
}

function handleImageUpload(event) {
  event.preventDefault(); // Prevent default form submission

  const formData = new FormData(event.target);

  fetch(event.target.action, {
    method: "POST",
    body: formData,
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.status === "success") {
        // Autofill the receiver address field
        document.getElementById("receiver_address_upload").value = data.address;
      } else {
        alert(data.message); // Handle any error messages
      }
    })
    .catch((error) => {
      console.error("Error:", error);
      alert("Error processing image. Please try again.");
    });
}

function handleDetectedAddress(address) {
  document.getElementById("address").value = address; // Set the detected address
  document.getElementById("detectedAddress").style.display = "block"; // Show the address
}

function showModal(message) {
  document.getElementById("modalMessage").innerText = message;
  document.getElementById("successModal").style.display = "block";
}

function closeModal() {
  document.getElementById("successModal").style.display = "none";
}

function toggleDropdown() {
  const dropdown = document.getElementById("profileDropdown");
  dropdown.style.display =
    dropdown.style.display === "block" ? "none" : "block";
}

function toggleBtcDropdown() {
  const dropdown = document.getElementById("btcDropdown");
  dropdown.style.display =
    dropdown.style.display === "block" ? "none" : "block";
}

// Close the dropdown if the user clicks outside of it
window.onclick = function (event) {
  if (!event.target.matches(".profile-button")) {
    const dropdown = document.getElementById("profileDropdown");
    if (dropdown.style.display === "block") {
      dropdown.style.display = "none";
    }
  }
};

// Close the dropdown if the user clicks outside of it
window.onclick = function (event) {
  if (!event.target.matches(".btc-button")) {
    const dropdown = document.getElementById("btcDropdown");
    if (dropdown.style.display === "block") {
      dropdown.style.display = "none";
    }
  }
};
