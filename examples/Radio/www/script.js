const musicContainer = document.getElementById('music-container');
const playBtn = document.getElementById('play');
const prevBtn = document.getElementById('prev');
const nextBtn = document.getElementById('next');

const audio = document.getElementById('audio');
const progress = document.getElementById('progress');
const progressContainer = document.getElementById('progress-container');
const title = document.getElementById('title');
const cover = document.getElementById('cover');


// Keep track of song
let songIndex = 0;


var data = "";
var datalen = 0;

function InitData (str) {
	data = JSON.parse(str);
	datalen = data["data"].length;
	loadSong(songIndex);
}
cinit();

// Update song details
function loadSong(i) {
  title.innerText = data["data"][i][0];
  audio.src = data["data"][i][1];
  cover.src = data["data"][i][2];
}

// Play song
function playSong() {
  musicContainer.classList.add('play');
  playBtn.querySelector('i.fas').classList.remove('fa-play');
  playBtn.querySelector('i.fas').classList.add('fa-pause');

  audio.play();
}

// Pause song
function pauseSong() {
  musicContainer.classList.remove('play');
  playBtn.querySelector('i.fas').classList.add('fa-play');
  playBtn.querySelector('i.fas').classList.remove('fa-pause');

  audio.pause();
}

// Previous song
function prevSong() {
  songIndex--;

  if (songIndex < 0) {
    songIndex = datalen - 1;
  }

  loadSong(songIndex);

  playSong();
}

// Next song
function nextSong() {
  songIndex++;

  if (songIndex > datalen - 1) {
    songIndex = 0;
  }

  loadSong(songIndex);

  playSong();
}

playBtn.addEventListener('click', () => {
  const isPlaying = musicContainer.classList.contains('play');

  if (isPlaying) {
    pauseSong();
  } else {
    playSong();
  }
});

prevBtn.addEventListener('click', prevSong);
nextBtn.addEventListener('click', nextSong);