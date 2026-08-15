const API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz123456";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const config = { apiKey: "pk_test_abcdefghijklmnopqrstuvwxyz" };

document.getElementById("out").innerHTML = userInput;

fetch("/api/data", {
  headers: { Authorization: "Bearer " + localStorage.getItem("token") },
});
