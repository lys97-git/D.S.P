/**
 * POST /pdf
 *
 * 두 가지 PDF 모드 지원:
 *   - 요약 PDF (default)  : body { job_id }
 *   - 상세 PDF            : body { job_id, type: "detail" }
 *
 * ── 캐싱 정책 ─────────────────────────────────────────────────
 *   요약 PDF  → scan_reports.report_path        에 캐시
 *   상세 PDF  → scan_reports.report_detail_path 에 캐시
 *   (만약 detail 컬럼이 DB에 없으면 캐시 건너뜀 — 매번 생성)
 */

const express  = require('express');
const supabase = require('../db/index');

const router = express.Router();

const SCANNER_URL    = process.env.PYTHON_SCANNER_URL || 'http://localhost:8000';
const STORAGE_BUCKET = process.env.SUPABASE_BUCKET    || 'reports';
const SIGNED_URL_TTL = 3600; // 1 hour

// ── POST /pdf ──────────────────────────────────────────────────
router.post('/', async (req, res) => {
  const jobId = req.body && req.body.job_id;
  const type  = (req.body && req.body.type) || 'summary';   // 'summary' | 'detail'
  const isDetail = type === 'detail';

  if (!jobId) {
    return res.status(400).json({ ok: false, error: 'job_id 필드가 필요합니다.' });
  }

  // 모드별 설정
  const scannerEndpoint   = isDetail ? '/report/generate-detail' : '/report/generate';
  const cacheColumn       = isDetail ? 'report_detail_path' : 'report_path';
  const downloadPrefix    = isDetail ? 'DSP_Detail' : 'DSP_Report';

  try {
    // ── 1. 캐시 확인 ────────────────────────────────────────────
    // scan_reports 행 + 캐시 컬럼 함께 조회 (없는 컬럼이면 null로 반환되어도 안전)
    const { data: report, error: rErr } = await supabase
      .from('scan_reports')
      .select(`id, scan_jobs_id, report_path, report_detail_path`)
      .eq('scan_jobs_id', jobId)
      .maybeSingle();

    // 'report_detail_path' 컬럼이 DB에 없으면 컬럼 에러가 날 수 있음
    // → fallback: report_path만 조회
    let reportRow = report;
    if (rErr && rErr.message && rErr.message.includes('report_detail_path')) {
      console.warn('[PDF] report_detail_path 컬럼 없음 — 캐시 비활성화로 진행');
      const fallback = await supabase
        .from('scan_reports')
        .select('id, scan_jobs_id, report_path')
        .eq('scan_jobs_id', jobId)
        .maybeSingle();
      if (fallback.error) throw new Error(`scan_reports 조회 실패: ${fallback.error.message}`);
      reportRow = fallback.data;
    } else if (rErr) {
      throw new Error(`scan_reports 조회 실패: ${rErr.message}`);
    }

    let storagePath = reportRow && reportRow[cacheColumn];
    const cached    = !!storagePath;

    // ── 2. 캐시 없음 → 스캐너에게 PDF 생성 요청 ─────────────────
    if (!cached) {
      console.log(`[PDF] job ${jobId} (${type}) 캐시 없음 — 스캐너 ${scannerEndpoint} 호출`);

      const scResp = await fetch(`${SCANNER_URL}${scannerEndpoint}`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ scan_job_id: jobId }),
      });

      if (!scResp.ok) {
        const txt = await scResp.text();
        throw new Error(`스캐너 응답 ${scResp.status}: ${txt.slice(0, 200)}`);
      }

      const scData = await scResp.json();
      if (scData.status !== 'success' || !scData.storage_path) {
        throw new Error(`스캐너 PDF 생성 실패: ${scData.detail || JSON.stringify(scData)}`);
      }
      storagePath = scData.storage_path;
      console.log(`[PDF] 스캐너 응답 storage_path=${storagePath}`);

      // 캐시 저장 시도 (컬럼 없을 수도 있으니 실패해도 무시)
      if (reportRow && reportRow.id) {
        const updatePayload = { [cacheColumn]: storagePath };
        const { error: updErr } = await supabase
          .from('scan_reports')
          .update(updatePayload)
          .eq('id', reportRow.id);
        if (updErr) {
          console.warn(`[PDF] scan_reports ${cacheColumn} 캐시 업데이트 실패: ${updErr.message}`);
        }
      } else {
        console.warn(`[PDF] scan_reports 행 없음 (job ${jobId}) — 캐시 보류`);
      }
    } else {
      console.log(`[PDF] job ${jobId} (${type}) 캐시 히트 — storage_path=${storagePath}`);
    }

    // ── 3. Signed URL 발급 ──────────────────────────────────────
    const downloadName = `${downloadPrefix}_${jobId.slice(0, 8)}.pdf`;
    const { data: urlData, error: urlErr } = await supabase
      .storage
      .from(STORAGE_BUCKET)
      .createSignedUrl(storagePath, SIGNED_URL_TTL, { download: downloadName });
    if (urlErr) throw new Error(`Signed URL 발급 실패: ${urlErr.message}`);

    // ── 4. 응답 ─────────────────────────────────────────────────
    res.json({
      ok:           true,
      job_id:       jobId,
      type,
      storage_path: storagePath,
      bucket:       STORAGE_BUCKET,
      url:          urlData.signedUrl,
      cached,
      expires_in:   SIGNED_URL_TTL,
    });

  } catch (e) {
    console.error(`[PDF] 에러 (${type}): ${e.message}`);
    res.status(500).json({ ok: false, error: e.message });
  }
});

module.exports = router;
// ──────────────────────────────────────────────────────────────
// POST /pdf/all
// 요약 PDF + 상세 PDF 를 한 번에 생성/캐시 조회하여 두 URL 반환.
// 프론트엔드는 응답의 summary.url, detail.url 두 개를 받아
// 순서대로 다운로드 트리거하면 됩니다.
// ──────────────────────────────────────────────────────────────
router.post('/all', async (req, res) => {
  const jobId = req.body && req.body.job_id;
  if (!jobId) {
    return res.status(400).json({ ok: false, error: 'job_id 필드가 필요합니다.' });
  }

  // 내부 호출용 헬퍼: 위에서 만든 / (POST /pdf) 라우트의 로직을 재사용하기 위해
  // 같은 작업을 함수로 캡슐화하지 않고, 간단하게 내부에서 두 번 처리합니다.
  async function generateOne(type) {
    const isDetail = type === 'detail';
    const scannerEndpoint = isDetail ? '/report/generate-detail' : '/report/generate';
    const cacheColumn     = isDetail ? 'report_detail_path' : 'report_path';
    const downloadPrefix  = isDetail ? 'DSP_Detail' : 'DSP_Report';

    // scan_reports 조회 (캐시 컬럼 두 개 다 가져옴)
    let reportRow = null;
    const { data, error } = await supabase
      .from('scan_reports')
      .select('id, scan_jobs_id, report_path, report_detail_path')
      .eq('scan_jobs_id', jobId)
      .maybeSingle();

    if (error && error.message && error.message.includes('report_detail_path')) {
      // detail 컬럼이 DB에 아직 없을 때 fallback
      const fb = await supabase
        .from('scan_reports')
        .select('id, scan_jobs_id, report_path')
        .eq('scan_jobs_id', jobId)
        .maybeSingle();
      if (fb.error) throw new Error(`scan_reports 조회 실패: ${fb.error.message}`);
      reportRow = fb.data;
    } else if (error) {
      throw new Error(`scan_reports 조회 실패: ${error.message}`);
    } else {
      reportRow = data;
    }

    let storagePath = reportRow && reportRow[cacheColumn];
    const cached    = !!storagePath;

    // 캐시 없으면 스캐너 호출
    if (!cached) {
      console.log(`[PDF/all] job ${jobId} (${type}) 캐시 없음 — 스캐너 ${scannerEndpoint} 호출`);
      const scResp = await fetch(`${SCANNER_URL}${scannerEndpoint}`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ scan_job_id: jobId }),
      });
      if (!scResp.ok) {
        const txt = await scResp.text();
        throw new Error(`스캐너(${type}) 응답 ${scResp.status}: ${txt.slice(0, 200)}`);
      }
      const scData = await scResp.json();
      if (scData.status !== 'success' || !scData.storage_path) {
        throw new Error(`스캐너(${type}) PDF 생성 실패: ${scData.detail || JSON.stringify(scData)}`);
      }
      storagePath = scData.storage_path;

      // 캐시 저장 (실패해도 무시)
      if (reportRow && reportRow.id) {
        const { error: updErr } = await supabase
          .from('scan_reports')
          .update({ [cacheColumn]: storagePath })
          .eq('id', reportRow.id);
        if (updErr) console.warn(`[PDF/all] ${cacheColumn} 캐시 업데이트 실패: ${updErr.message}`);
      }
    } else {
      console.log(`[PDF/all] job ${jobId} (${type}) 캐시 히트`);
    }

    // Signed URL 발급
    const downloadName = `${downloadPrefix}_${jobId.slice(0, 8)}.pdf`;
    const { data: urlData, error: urlErr } = await supabase
      .storage
      .from(STORAGE_BUCKET)
      .createSignedUrl(storagePath, SIGNED_URL_TTL, { download: downloadName });
    if (urlErr) throw new Error(`Signed URL 발급 실패(${type}): ${urlErr.message}`);

    return {
      type,
      storage_path: storagePath,
      url: urlData.signedUrl,
      cached,
    };
  }

  try {
    // 두 PDF 를 병렬 생성 (각각 캐시/스캐너 호출)
    const [summary, detail] = await Promise.all([
      generateOne('summary'),
      generateOne('detail'),
    ]);

    res.json({
      ok:         true,
      job_id:     jobId,
      bucket:     STORAGE_BUCKET,
      expires_in: SIGNED_URL_TTL,
      summary,
      detail,
    });
  } catch (e) {
    console.error(`[PDF/all] 에러: ${e.message}`);
    res.status(500).json({ ok: false, error: e.message });
  }
});
