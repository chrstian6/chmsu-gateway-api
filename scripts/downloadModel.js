const fs = require("fs");
const path = require("path");
const https = require("https");

const modelsDir = path.join(__dirname, "..", "models");

const files = [
  "ssd_mobilenetv1_model-shard1",
  "face_landmark_68_model-shard1",
  "face_recognition_model-shard1",
  "face_recognition_model-shard2",
  "ssd_mobilenetv1_model-weights_manifest.json",
  "face_landmark_68_model-weights_manifest.json",
  "face_recognition_model-weights_manifest.json",
];

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https
      .get(url, (response) => {
        response.pipe(file);
        file.on("finish", () => {
          file.close();
          resolve();
        });
      })
      .on("error", (err) => {
        fs.unlink(dest, () => reject(err));
      });
  });
}

async function downloadAll() {
  if (!fs.existsSync(modelsDir)) {
    fs.mkdirSync(modelsDir, { recursive: true });
  }

  const baseUrl =
    "https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights/";

  for (const file of files) {
    const url = baseUrl + file;
    const dest = path.join(modelsDir, file);

    if (!fs.existsSync(dest)) {
      console.log(`Downloading ${file}...`);
      await downloadFile(url, dest);
      console.log(`✅ ${file}`);
    } else {
      console.log(`⏭️  ${file} (exists)`);
    }
  }

  console.log("✅ All models downloaded");
}

downloadAll().catch(console.error);
