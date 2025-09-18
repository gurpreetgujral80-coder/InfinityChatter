from flask import Flask, request, render_template_string, send_from_directory
from moviepy.editor import VideoFileClip, TextClip, CompositeVideoClip
from googletrans import Translator
import speech_recognition as sr
from pydub import AudioSegment
import os
import uuid

app = Flask(__name__)
translator = Translator()

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "video" not in request.files:
            return render_template("index.html", error="No video file provided.")

        video_file = request.files["video"]
        if video_file.filename == "":
            return render_template("index.html", error="No selected file.")

        # Save uploaded file
        unique_id = str(uuid.uuid4())[:8]
        video_path = os.path.join(UPLOAD_FOLDER, f"{unique_id}_{video_file.filename}")
        output_path = os.path.join(OUTPUT_FOLDER, f"subtitled_{unique_id}.mp4")
        video_file.save(video_path)

        try:
            video_clip = VideoFileClip(video_path)
            subtitles = generate_subtitles(video_clip)
            create_video_with_subtitles(video_clip, subtitles, output_path)

            # Render page with preview
            return render_template(
                "index.html",
                video_url=f"/outputs/subtitled_{unique_id}.mp4",
                success="✅ Video generated successfully!"
            )
        except Exception as e:
            return render_template("index.html", error=f"Error: {str(e)}")
        finally:
            if os.path.exists(video_path):
                os.remove(video_path)

    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>AI Subtitle Generator</title>
          <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
          <style>
            body { background: #f9f9f9; }
            .container { max-width: 800px; margin-top: 60px; }
            .card { border-radius: 15px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
            .btn-primary { border-radius: 10px; padding: 10px 20px; font-size: 18px; }
            video { width: 100%; border-radius: 10px; margin-top: 20px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="card p-4">
              <h2 class="text-center mb-4">🎬 AI Subtitle Generator</h2>
              <p class="text-center text-muted">Upload your video and get automatic English subtitles.</p>
        
              {% if error %}
                <div class="alert alert-danger">{{ error }}</div>
              {% endif %}
              {% if success %}
                <div class="alert alert-success">{{ success }}</div>
              {% endif %}
        
              <form method="POST" enctype="multipart/form-data" class="mb-3">
                <div class="mb-3">
                  <input class="form-control" type="file" name="video" accept="video/*" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Upload & Generate</button>
              </form>
        
              {% if video_url %}
                <h4 class="mt-4">Preview:</h4>
                <video controls>
                  <source src="{{ video_url }}" type="video/mp4">
                  Your browser does not support the video tag.
                </video>
              {% endif %}
            </div>
          </div>
        </body>
        </html>
        ''')


@app.route("/outputs/<filename>")
def serve_output(filename):
    return send_from_directory(OUTPUT_FOLDER, filename)


# ----------- Subtitle Helpers -----------

def generate_subtitles(video_clip):
    audio_path = "temp_audio.wav"
    video_clip.audio.write_audiofile(audio_path, fps=16000)

    audio = AudioSegment.from_wav(audio_path)
    recognizer = sr.Recognizer()
    chunk_length_ms = 5000  # 5 seconds
    subtitles = []

    for i, chunk in enumerate(audio[::chunk_length_ms]):
        chunk_path = f"chunk_{i}.wav"
        chunk.export(chunk_path, format="wav")

        with sr.AudioFile(chunk_path) as source:
            audio_data = recognizer.record(source)

        try:
            text = recognizer.recognize_google(audio_data)
        except Exception:
            text = "[unrecognized]"

        os.remove(chunk_path)

        words = text.split()
        translated_line = []
        for word in words:
            if not word.isascii():
                translated_word = translator.translate(word, src='auto', dest='en').text
                translated_line.append(translated_word)
            else:
                translated_line.append(word)

        start_time = i * (chunk_length_ms / 1000.0)
        end_time = min((i + 1) * (chunk_length_ms / 1000.0), video_clip.duration)

        subtitles.append({"start": start_time, "end": end_time, "text": " ".join(translated_line)})

    os.remove(audio_path)
    return subtitles


def create_video_with_subtitles(video_clip, subtitles, output_path):
    clips = [video_clip]

    for sub in subtitles:
        txt_clip = TextClip(
            sub["text"],
            fontsize=30,
            color="white",
            stroke_color="black",
            stroke_width=2,
            method="caption",
            size=(video_clip.w * 0.9, None)
        ).set_position(("center", "bottom")).set_start(sub["start"]).set_duration(sub["end"] - sub["start"])
        clips.append(txt_clip)

    final_clip = CompositeVideoClip(clips)
    final_clip.write_videofile(output_path, codec="libx264", audio_codec="aac")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
