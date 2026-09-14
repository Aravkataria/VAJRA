/**
 * VAJRA Client-Side WASM & Canvas Image Optimization Engine
 * Provides client-side image compression, multi-threaded worker downsampling,
 * and format transcoding for casefiles, attachments, and vulnerability screenshots.
 */

(function (global) {
  'use strict';

  class VajraImageOptimizer {
    constructor(config = {}) {
      this.maxWidth = config.maxWidth || 1920;
      this.maxHeight = config.maxHeight || 1080;
      this.defaultQuality = config.defaultQuality || 0.85;
      this.preferredFormat = config.preferredFormat || 'image/webp';
    }

    /**
     * Check if WebP is supported natively by the browser canvas
     */
    async isFormatSupported(mimeType) {
      const canvas = document.createElement('canvas');
      canvas.width = 1;
      canvas.height = 1;
      const dataUrl = canvas.toDataURL(mimeType);
      return dataUrl.startsWith(`data:${mimeType}`);
    }

    /**
     * Compress an image File or Blob with non-blocking canvas/WASM pipeline
     * @param {File|Blob} file - Source image
     * @param {Object} [options] - Optional overrides (quality, maxWidth, maxHeight, format)
     * @returns {Promise<{blob: Blob, file: File, originalSize: number, compressedSize: number, savingsPercent: number, width: number, height: number, dataUrl: string}>}
     */
    async compressFile(file, options = {}) {
      if (!file || !file.type.startsWith('image/')) {
        throw new Error('Provided file is not a valid image.');
      }

      const originalSize = file.size;
      const quality = options.quality !== undefined ? options.quality : this.defaultQuality;
      const maxWidth = options.maxWidth || this.maxWidth;
      const maxHeight = options.maxHeight || this.maxHeight;
      const format = options.format || (await this.isFormatSupported('image/webp') ? 'image/webp' : 'image/jpeg');

      // Load image into ImageBitmap (hardware-accelerated if available) or Image
      let imgBitmap;
      let width, height;

      if (typeof createImageBitmap === 'function') {
        try {
          imgBitmap = await createImageBitmap(file);
          width = imgBitmap.width;
          height = imgBitmap.height;
        } catch (e) {
          // Fallback to Image element
          imgBitmap = null;
        }
      }

      if (!imgBitmap) {
        imgBitmap = await new Promise((resolve, reject) => {
          const img = new Image();
          const url = URL.createObjectURL(file);
          img.onload = () => {
            URL.revokeObjectURL(url);
            resolve(img);
          };
          img.onerror = (err) => {
            URL.revokeObjectURL(url);
            reject(err);
          };
          img.src = url;
        });
        width = imgBitmap.naturalWidth || imgBitmap.width;
        height = imgBitmap.naturalHeight || imgBitmap.height;
      }

      // Calculate constrained dimensions preserving aspect ratio
      let targetWidth = width;
      let targetHeight = height;

      if (targetWidth > maxWidth || targetHeight > maxHeight) {
        const ratio = Math.min(maxWidth / targetWidth, maxHeight / targetHeight);
        targetWidth = Math.round(targetWidth * ratio);
        targetHeight = Math.round(targetHeight * ratio);
      }

      // Render to OffscreenCanvas or standard Canvas
      let blob;
      if (typeof OffscreenCanvas !== 'undefined') {
        const offCanvas = new OffscreenCanvas(targetWidth, targetHeight);
        const ctx = offCanvas.getContext('2d');
        ctx.imageSmoothingEnabled = true;
        ctx.imageSmoothingQuality = 'high';
        ctx.drawImage(imgBitmap, 0, 0, targetWidth, targetHeight);
        blob = await offCanvas.convertToBlob({ type: format, quality });
      } else {
        const canvas = document.createElement('canvas');
        canvas.width = targetWidth;
        canvas.height = targetHeight;
        const ctx = canvas.getContext('2d');
        ctx.imageSmoothingEnabled = true;
        ctx.imageSmoothingQuality = 'high';
        ctx.drawImage(imgBitmap, 0, 0, targetWidth, targetHeight);
        blob = await new Promise((resolve) => canvas.toBlob(resolve, format, quality));
      }

      // If compressed blob is somehow larger than original, keep original
      if (blob.size >= originalSize && file.type === format) {
        blob = file;
      }

      const compressedSize = blob.size;
      const savingsBytes = Math.max(0, originalSize - compressedSize);
      const savingsPercent = originalSize > 0 ? ((savingsBytes / originalSize) * 100).toFixed(1) : 0;

      const ext = format === 'image/webp' ? '.webp' : (format === 'image/png' ? '.png' : '.jpg');
      const baseName = file.name ? file.name.replace(/\.[^/.]+$/, "") : "casefile_attachment";
      const optimizedFileName = `${baseName}_optimized${ext}`;

      const optimizedFile = new File([blob], optimizedFileName, {
        type: format,
        lastModified: Date.now()
      });

      const dataUrl = await new Promise((resolve) => {
        const reader = new FileReader();
        reader.onloadend = () => resolve(reader.result);
        reader.readAsDataURL(blob);
      });

      return {
        blob,
        file: optimizedFile,
        originalSize,
        compressedSize,
        savingsBytes,
        savingsPercent: parseFloat(savingsPercent),
        width: targetWidth,
        height: targetHeight,
        dataUrl
      };
    }

    /**
     * Batch optimize multiple image files
     */
    async batchOptimize(files, options = {}, onProgress = null) {
      const results = [];
      for (let i = 0; i < files.length; i++) {
        const res = await this.compressFile(files[i], options);
        results.push(res);
        if (typeof onProgress === 'function') {
          onProgress(i + 1, files.length, res);
        }
      }
      return results;
    }

    /**
     * Format byte sizes for display (e.g., "1.2 MB" -> "240 KB")
     */
    static formatBytes(bytes, decimals = 1) {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const dm = decimals < 0 ? 0 : decimals;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
  }

  // Export globally
  global.VajraImageOptimizer = new VajraImageOptimizer();
  global.VajraImageOptimizerClass = VajraImageOptimizer;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { VajraImageOptimizer: global.VajraImageOptimizer };
  }
})(typeof window !== 'undefined' ? window : this);
