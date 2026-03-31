const fs = require('fs');
const path = require('path');

/**
 * MARKET_S3_BUCKET, AWS_REGION, 자격 증명이 있으면 로컬 파일을 S3에 올리고 public URL 반환.
 * 그렇지 않으면 null (호출측에서 로컬 URL 유지).
 */
async function tryUploadVideoToS3(localFilePath, originalName) {
  const bucket = process.env.MARKET_S3_BUCKET || process.env.AWS_S3_BUCKET;
  if (!bucket) return null;
  try {
    const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
    const region = process.env.AWS_REGION || 'ap-northeast-2';
    const client = new S3Client({ region });
    const key = `market-videos/${Date.now()}_${path.basename(originalName || 'video.bin')}`;
    const body = fs.readFileSync(localFilePath);
    await client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: body,
        ContentType: 'video/mp4',
      }),
    );
    const base = (process.env.MARKET_S3_PUBLIC_BASE || '').replace(/\/$/, '');
    if (base) return `${base}/${key}`;
    return `s3://${bucket}/${key}`;
  } catch (e) {
    console.warn('[market s3]', e.message);
    return null;
  }
}

module.exports = { tryUploadVideoToS3 };
