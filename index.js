// phishing-detector-backend/index.js (FINAL DENGAN PERBAIKAN BUG)

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const querystring = require('querystring');
require('dotenv').config();

const app = express();
const PORT = 8080;

app.use(cors());
app.use(express.json());

const virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;

// ENDPOINT #1: Untuk memulai scan
app.post('/scan-url', async (req, res) => {
  const { url: urlToScan } = req.body;
  if (!urlToScan) return res.status(400).json({ error: 'URL tidak boleh kosong' });

  const urlId = crypto.createHash('sha256').update(urlToScan).digest('hex');
  const getReportUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;
  
  try {
    const response = await axios.get(getReportUrl, { headers: { 'x-apikey': virusTotalApiKey } });
    console.log(`[GET] Laporan ditemukan untuk ${urlToScan}`);
    res.json({ status: 'completed', data: response.data });
  } catch (error) {
    if (error.response && error.response.status === 404) {
      console.log(`[GET] Laporan tidak ditemukan. Memulai analisis baru untuk ${urlToScan}`);
      const postUrlForAnalysis = 'https://www.virustotal.com/api/v3/urls';
      try {
        const analysisResponse = await axios.post(postUrlForAnalysis, querystring.stringify({ url: urlToScan }), {
          headers: {
            'x-apikey': virusTotalApiKey,
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        });
        const analysisId = analysisResponse.data.data.id;
        console.log(`[POST] Analisis baru dimulai dengan ID: ${analysisId}`);
        res.json({ status: 'pending', analysisId: analysisId });
      } catch (postError) {
        console.error('[POST] Gagal memulai analisis baru:', postError.message);
        res.status(500).json({ error: 'Gagal memulai analisis baru.' });
      }
    } else {
      console.error('[GET] Error tidak terduga:', error.message);
      res.status(500).json({ error: 'Terjadi kesalahan tidak terduga pada server.' });
    }
  }
});

// ENDPOINT #2: Untuk mengecek hasil analisis secara berkala (polling)
app.get('/check-result/:id', async (req, res) => {
    const analysisId = req.params.id;
    console.log(`[POLL] Mengecek hasil untuk ID Analisis: ${analysisId}`);
    const getAnalysisUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;

    try {
        const response = await axios.get(getAnalysisUrl, { headers: { 'x-apikey': virusTotalApiKey } });
        const attributes = response.data.data.attributes;

        if (attributes.status === 'completed') {
            console.log(`[POLL] Analisis selesai untuk ID: ${analysisId}`);
            
            // --- BAGIAN YANG DIPERBAIKI ---
            // Kita ambil ID Laporan URL dari metadata hasil analisis, bukan dari attributes.links.item
            const urlId = response.data.meta.url_info.id;
            const finalReportUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;
            
            console.log(`[POLL] Mengambil laporan final dari: ${finalReportUrl}`);
            const finalReport = await axios.get(finalReportUrl, { headers: { 'x-apikey': virusTotalApiKey } });
            res.json({ status: 'completed', data: finalReport.data });
            // --- AKHIR BAGIAN YANG DIPERBAIKI ---

        } else {
            console.log(`[POLL] Analisis masih berjalan (status: ${attributes.status})`);
            res.json({ status: 'pending' }); // Masih pending, frontend akan coba lagi
        }
    } catch (error) {
        console.error('[POLL] Error saat mengecek hasil:', error.message);
        res.status(500).json({ error: 'Gagal mengecek hasil analisis.' });
    }
});


app.listen(PORT, () => {
  console.log(`Server berjalan di port ${PORT}`);
});