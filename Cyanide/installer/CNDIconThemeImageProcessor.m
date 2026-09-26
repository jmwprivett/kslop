//
//  CNDIconThemeImageProcessor.m
//  Cyanide
//
//  A small, bounded PNG implementation used by SnowBoard Remix.  ImageIO is
//  intentionally not used here: decoding an untrusted IHDR through a high
//  level image API can allocate before the caller has had an opportunity to
//  enforce a memory limit.  The parser below validates the complete PNG
//  stream, checks all arithmetic, and only then allocates scanline/RGBA
//  buffers.
//

#import "CNDIconThemeImageProcessor.h"

#import <stdint.h>
#import <string.h>
#import <stdlib.h>
#import <limits.h>
#import <math.h>
#import <zlib.h>

NSString * const CNDIconThemeImageProcessorErrorDomain =
    @"CNDIconThemeImageProcessorErrorDomain";

const NSUInteger CNDIconThemeImageProcessorMaximumDimension = 8192;
const NSUInteger CNDIconThemeImageProcessorMaximumPixels = 16777216;

static const NSUInteger kCNDMaximumInputBytes = 128u * 1024u * 1024u;
static const NSUInteger kCNDMaximumDecodedBytes = 128u * 1024u * 1024u;
static const NSUInteger kCNDMaximumChunkBytes = 64u * 1024u * 1024u;
static const NSUInteger kCNDMaximumPaletteEntries = 256u;

typedef struct {
    uint32_t width;
    uint32_t height;
    uint8_t bitDepth;
    uint8_t colorType;
    uint8_t interlace;
    uint8_t palette[768];
    uint8_t paletteAlpha[256];
    NSUInteger paletteCount;
    NSUInteger paletteAlphaCount;
    uint16_t transparentGray;
    uint16_t transparentRed;
    uint16_t transparentGreen;
    uint16_t transparentBlue;
    BOOL hasTransparentGray;
    BOOL hasTransparentRGB;
    BOOL hasSRGB;
    uint32_t gammaTimes100000;
    uint8_t orientation;
    NSUInteger expectedInflatedBytes;
    NSUInteger unpaddedLength;
} CNDPNGInfo;

typedef struct {
    NSUInteger width;
    NSUInteger height;
    uint8_t *rgba;
} CNDImage;

typedef struct {
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
    // The palette builder works in premultiplied RGBA space.  Keeping the
    // premultiplied representative alongside the straight-alpha value avoids
    // repeatedly rounding transparent-edge colors during box splitting and
    // nearest-colour selection.
    uint8_t premultiplied[3];
    uint64_t count;
    uint32_t firstPixel;
    uint64_t sumPremultiplied[3];
    uint64_t sumAlpha;
} CNDColorEntry;

typedef struct {
    NSUInteger *indices;
    NSUInteger start;
    NSUInteger count;
    uint8_t minChannel[4];
    uint8_t maxChannel[4];
    uint64_t weight;
} CNDColorBox;

typedef struct {
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
} CNDPaletteColor;

// The histogram is deliberately a fixed, bounded 4-D binning grid.  The
// previous implementation retained only the first paletteLimit*16 exact
// colours, which meant that a later section of a gradient could be absent
// from the palette altogether.  Four-bit premultiplied colour bins plus a
// six-bit alpha axis retain useful edge/opacity resolution while keeping the
// worst-case histogram allocation bounded (approximately 15 MiB on arm64).
static const NSUInteger kCNDHistogramRGBBins = 16u;
static const NSUInteger kCNDHistogramAlphaBins = 64u;
static const NSUInteger kCNDHistogramBinCount =
    16u * 16u * 16u * 64u;

static BOOL CNDSetError(NSError **error,
                        CNDIconThemeImageProcessorError code,
                        NSString *message)
{
    if (error) {
        *error = [NSError errorWithDomain:CNDIconThemeImageProcessorErrorDomain
                                     code:code
                                 userInfo:@{ NSLocalizedDescriptionKey :
                                                 message ?: @"Icon image processing failed." }];
    }
    return NO;
}

static BOOL CNDAddSize(NSUInteger a, NSUInteger b, NSUInteger *out)
{
    if (b > SIZE_MAX - a) return NO;
    if (out) *out = a + b;
    return YES;
}

static BOOL CNDMultiplySize(NSUInteger a, NSUInteger b, NSUInteger *out)
{
    if (a != 0 && b > SIZE_MAX / a) return NO;
    if (out) *out = a * b;
    return YES;
}

static uint32_t CNDReadBE32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static uint16_t CNDReadBE16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t CNDReadLE32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint16_t CNDReadLE16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static BOOL CNDChunkNameIs(const uint8_t *name, const char *literal)
{
    return memcmp(name, literal, 4) == 0;
}

static NSUInteger CNDChannelsForColorType(uint8_t colorType)
{
    switch (colorType) {
        case 0: return 1;
        case 2: return 3;
        case 3: return 1;
        case 4: return 2;
        case 6: return 4;
        default: return 0;
    }
}

static BOOL CNDBitsPerPixel(const CNDPNGInfo *info, NSUInteger *bitsOut,
                            NSUInteger *bytesPerPixelOut)
{
    NSUInteger channels = CNDChannelsForColorType(info->colorType);
    NSUInteger bits = 0;
    if (channels == 0 || info->bitDepth == 0 ||
        !CNDMultiplySize(channels, info->bitDepth, &bits)) return NO;
    if (bitsOut) *bitsOut = bits;
    if (bytesPerPixelOut) *bytesPerPixelOut = MAX((NSUInteger)1, (bits + 7u) / 8u);
    return YES;
}

static BOOL CNDRowBytes(NSUInteger width, NSUInteger bitsPerPixel,
                        NSUInteger *rowBytesOut)
{
    NSUInteger bits = 0;
    if (!CNDMultiplySize(width, bitsPerPixel, &bits)) return NO;
    if (bits > SIZE_MAX - 7u) return NO;
    if (rowBytesOut) *rowBytesOut = (bits + 7u) / 8u;
    return YES;
}

static BOOL CNDPassDimensions(NSUInteger width, NSUInteger height,
                              NSUInteger startX, NSUInteger startY,
                              NSUInteger stepX, NSUInteger stepY,
                              NSUInteger *passWidth, NSUInteger *passHeight)
{
    NSUInteger pw = 0;
    NSUInteger ph = 0;
    if (width > startX) pw = (width - startX + stepX - 1u) / stepX;
    if (height > startY) ph = (height - startY + stepY - 1u) / stepY;
    if (passWidth) *passWidth = pw;
    if (passHeight) *passHeight = ph;
    return YES;
}

static BOOL CNDExpectedInflatedBytes(CNDPNGInfo *info)
{
    NSUInteger bitsPerPixel = 0;
    if (!CNDBitsPerPixel(info, &bitsPerPixel, NULL)) return NO;

    NSUInteger total = 0;
    if (info->interlace == 0) {
        NSUInteger rowBytes = 0;
        if (!CNDRowBytes(info->width, bitsPerPixel, &rowBytes)) return NO;
        NSUInteger rowWithFilter = 0;
        if (!CNDAddSize(rowBytes, 1u, &rowWithFilter) ||
            !CNDMultiplySize(rowWithFilter, info->height, &total)) return NO;
    } else {
        static const uint8_t startsX[7] = { 0, 4, 0, 2, 0, 1, 0 };
        static const uint8_t startsY[7] = { 0, 0, 4, 0, 2, 0, 1 };
        static const uint8_t stepsX[7]  = { 8, 8, 4, 4, 2, 2, 1 };
        static const uint8_t stepsY[7]  = { 8, 8, 4, 4, 2, 2, 1 };
        for (NSUInteger pass = 0; pass < 7; pass++) {
            NSUInteger pw = 0;
            NSUInteger ph = 0;
            CNDPassDimensions(info->width, info->height,
                              startsX[pass], startsY[pass],
                              stepsX[pass], stepsY[pass], &pw, &ph);
            if (pw == 0 || ph == 0) continue;
            NSUInteger rowBytes = 0;
            if (!CNDRowBytes(pw, bitsPerPixel, &rowBytes)) return NO;
            NSUInteger rowWithFilter = 0;
            NSUInteger passBytes = 0;
            if (!CNDAddSize(rowBytes, 1u, &rowWithFilter) ||
                !CNDMultiplySize(rowWithFilter, ph, &passBytes) ||
                !CNDAddSize(total, passBytes, &total)) return NO;
        }
    }
    if (total == 0 || total > kCNDMaximumDecodedBytes) return NO;
    info->expectedInflatedBytes = total;
    return YES;
}

static BOOL CNDValidatePNGHeader(CNDPNGInfo *info, NSError **error)
{
    if (info->width == 0 || info->height == 0 ||
        info->width > CNDIconThemeImageProcessorMaximumDimension ||
        info->height > CNDIconThemeImageProcessorMaximumDimension) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"PNG dimensions exceed the icon processor limit.");
    }
    NSUInteger pixels = 0;
    if (!CNDMultiplySize(info->width, info->height, &pixels) ||
        pixels > CNDIconThemeImageProcessorMaximumPixels) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"PNG pixel count exceeds the icon processor limit.");
    }

    NSUInteger channels = CNDChannelsForColorType(info->colorType);
    BOOL validDepth = NO;
    switch (info->colorType) {
        case 0: validDepth = info->bitDepth == 1 || info->bitDepth == 2 ||
                                   info->bitDepth == 4 || info->bitDepth == 8 ||
                                   info->bitDepth == 16; break;
        case 2: validDepth = info->bitDepth == 8 || info->bitDepth == 16; break;
        case 3: validDepth = info->bitDepth == 1 || info->bitDepth == 2 ||
                                   info->bitDepth == 4 || info->bitDepth == 8; break;
        case 4: validDepth = info->bitDepth == 8 || info->bitDepth == 16; break;
        case 6: validDepth = info->bitDepth == 8 || info->bitDepth == 16; break;
        default: validDepth = NO; break;
    }
    if (!validDepth || channels == 0) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorUnsupportedPNG,
                           @"PNG color type or bit depth is unsupported.");
    }
    if (info->interlace > 1) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorUnsupportedPNG,
                           @"PNG interlace method is unsupported.");
    }
    if (!CNDExpectedInflatedBytes(info)) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"PNG scanline storage exceeds the icon processor limit.");
    }
    if (info->colorType == 3 && info->paletteCount > (1u << info->bitDepth)) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                           @"The PNG palette has more entries than its bit depth permits.");
    }
    return YES;
}

static uint16_t CNDTIFF16(const uint8_t *p, BOOL little)
{
    return little ? CNDReadLE16(p) : CNDReadBE16(p);
}

static uint32_t CNDTIFF32(const uint8_t *p, BOOL little)
{
    return little ? CNDReadLE32(p) : CNDReadBE32(p);
}

static uint8_t CNDPngEXIFOrientation(const uint8_t *bytes, NSUInteger length)
{
    // PNG eXIf contains a TIFF stream without the usual Exif header.
    if (length < 8) return 1;
    BOOL little = NO;
    if (bytes[0] == 'I' && bytes[1] == 'I') little = YES;
    else if (bytes[0] == 'M' && bytes[1] == 'M') little = NO;
    else return 1;
    if (CNDTIFF16(bytes + 2, little) != 42u) return 1;
    uint32_t ifdOffset = CNDTIFF32(bytes + 4, little);
    if (ifdOffset > length - 2u) return 1;
    const uint8_t *ifd = bytes + ifdOffset;
    NSUInteger remaining = length - ifdOffset;
    if (remaining < 2) return 1;
    uint16_t count = CNDTIFF16(ifd, little);
    NSUInteger entriesBytes = 0;
    if (!CNDMultiplySize(count, 12u, &entriesBytes) ||
        entriesBytes > remaining - 2u) return 1;
    for (NSUInteger i = 0; i < count; i++) {
        const uint8_t *entry = ifd + 2u + i * 12u;
        uint16_t tag = CNDTIFF16(entry, little);
        if (tag != 0x0112u) continue;
        uint16_t type = CNDTIFF16(entry + 2u, little);
        uint32_t itemCount = CNDTIFF32(entry + 4u, little);
        if (type != 3u || itemCount < 1u) return 1;
        uint16_t value = 0;
        if (itemCount == 1u) value = CNDTIFF16(entry + 8u, little);
        else {
            uint32_t offset = CNDTIFF32(entry + 8u, little);
            if (offset > length - 2u) return 1;
            value = CNDTIFF16(bytes + offset, little);
        }
        return (value >= 1u && value <= 8u) ? (uint8_t)value : 1;
    }
    return 1;
}

static BOOL CNDParsePNG(NSData *data, BOOL allowZeroPadding,
                        CNDPNGInfo *outInfo, NSData **outIDAT, NSError **error)
{
    if (!outInfo || !outIDAT) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                           @"PNG parser output arguments are invalid.");
    }
    memset(outInfo, 0, sizeof(*outInfo));
    *outIDAT = nil;
    if (!data || data.length < 33u || data.length > kCNDMaximumInputBytes) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                           @"PNG data is empty, truncated, or too large.");
    }
    const uint8_t *bytes = data.bytes;
    static const uint8_t signature[8] = {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
    };
    if (memcmp(bytes, signature, sizeof(signature)) != 0) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                           @"The image is not a PNG.");
    }

    NSMutableData *idat = [NSMutableData data];
    NSUInteger offset = 8u;
    BOOL sawIHDR = NO;
    BOOL sawIDAT = NO;
    BOOL leftIDAT = NO;
    BOOL sawIEND = NO;
    BOOL sawPLTE = NO;
    BOOL sawTRNS = NO;
    BOOL sawEXIF = NO;
    BOOL sawGAMA = NO;
    BOOL sawSRGB = NO;
    while (offset < data.length) {
        if (data.length - offset < 12u) {
            return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                               @"PNG chunk header is truncated.");
        }
        const uint8_t *chunk = bytes + offset;
        uint32_t chunkLength32 = CNDReadBE32(chunk);
        NSUInteger chunkLength = (NSUInteger)chunkLength32;
        if (chunkLength > kCNDMaximumChunkBytes ||
            chunkLength > data.length - offset - 12u) {
            return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                               @"PNG chunk length is invalid.");
        }
        const uint8_t *name = chunk + 4u;
        for (NSUInteger i = 0; i < 4u; i++) {
            if (!((name[i] >= 'A' && name[i] <= 'Z') ||
                  (name[i] >= 'a' && name[i] <= 'z'))) {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                   @"PNG chunk type is invalid.");
            }
        }
        // Unknown critical chunks cannot be safely ignored.  Ancillary
        // chunks (lower-case first byte) are intentionally tolerated unless
        // they carry semantics that this decoder cannot preserve.
        BOOL knownCritical = CNDChunkNameIs(name, "IHDR") ||
                             CNDChunkNameIs(name, "PLTE") ||
                             CNDChunkNameIs(name, "IDAT") ||
                             CNDChunkNameIs(name, "IEND");
        if ((name[0] >= 'A' && name[0] <= 'Z') && !knownCritical) {
            return CNDSetError(error, CNDIconThemeImageProcessorErrorUnsupportedPNG,
                               @"PNG contains an unknown critical chunk.");
        }
        const uint8_t *payload = chunk + 8u;
        uint32_t expectedCRC = CNDReadBE32(payload + chunkLength);
        uLong actualCRC = crc32(0L, Z_NULL, 0);
        actualCRC = crc32(actualCRC, name, 4u);
        if (chunkLength > 0) actualCRC = crc32(actualCRC, payload, (uInt)chunkLength);
        if ((uint32_t)actualCRC != expectedCRC) {
            return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                               @"PNG chunk CRC verification failed.");
        }

        if (CNDChunkNameIs(name, "IHDR")) {
            if (sawIHDR || chunkLength != 13u || offset != 8u) {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                   @"PNG has an invalid IHDR position or length.");
            }
            sawIHDR = YES;
            outInfo->width = CNDReadBE32(payload);
            outInfo->height = CNDReadBE32(payload + 4u);
            outInfo->bitDepth = payload[8];
            outInfo->colorType = payload[9];
            if (payload[10] != 0 || payload[11] != 0) {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorUnsupportedPNG,
                                   @"PNG compression or filter method is unsupported.");
            }
            outInfo->interlace = payload[12];
            if (!CNDValidatePNGHeader(outInfo, error)) return NO;
        } else if (CNDChunkNameIs(name, "PLTE")) {
            if (!sawIHDR || sawPLTE || sawIDAT || chunkLength == 0 ||
                chunkLength > sizeof(outInfo->palette) || chunkLength % 3u != 0) {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                   @"PNG PLTE chunk is invalid or out of order.");
            }
            sawPLTE = YES;
            outInfo->paletteCount = chunkLength / 3u;
            memcpy(outInfo->palette, payload, chunkLength);
        } else if (CNDChunkNameIs(name, "tRNS")) {
            if (!sawIHDR || sawTRNS || sawIDAT) {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                   @"PNG tRNS chunk is invalid or out of order.");
            }
            sawTRNS = YES;
            if (outInfo->colorType == 0) {
                if (chunkLength != 2u) {
                    return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                       @"Grayscale PNG tRNS length is invalid.");
                }
                outInfo->transparentGray = CNDReadBE16(payload);
                outInfo->hasTransparentGray = YES;
            } else if (outInfo->colorType == 2) {
                if (chunkLength != 6u) {
                    return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                       @"RGB PNG tRNS length is invalid.");
                }
                outInfo->transparentRed = CNDReadBE16(payload);
                outInfo->transparentGreen = CNDReadBE16(payload + 2u);
                outInfo->transparentBlue = CNDReadBE16(payload + 4u);
                outInfo->hasTransparentRGB = YES;
            } else if (outInfo->colorType == 3) {
                if (chunkLength > sizeof(outInfo->paletteAlpha)) {
                    return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                       @"Palette PNG tRNS table is too large.");
                }
                outInfo->paletteAlphaCount = chunkLength;
                memcpy(outInfo->paletteAlpha, payload, chunkLength);
            } else {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                   @"PNG tRNS is not valid for this color type.");
            }
        } else if (CNDChunkNameIs(name, "gAMA")) {
            if (sawGAMA || chunkLength != 4u) {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                   @"PNG gAMA chunk is invalid or duplicated.");
            }
            sawGAMA = YES;
            outInfo->gammaTimes100000 = CNDReadBE32(payload);
        } else if (CNDChunkNameIs(name, "sRGB")) {
            if (sawSRGB || chunkLength != 1u || payload[0] > 3u) {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                   @"PNG sRGB chunk is invalid or duplicated.");
            }
            sawSRGB = YES;
            outInfo->hasSRGB = YES;
        } else if (CNDChunkNameIs(name, "eXIf")) {
            if (sawEXIF) {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                   @"PNG contains more than one eXIf chunk.");
            }
            sawEXIF = YES;
            outInfo->orientation = CNDPngEXIFOrientation(payload, chunkLength);
        } else if (CNDChunkNameIs(name, "IDAT")) {
            if (!sawIHDR || leftIDAT) {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                   @"PNG IDAT chunk is invalid or not contiguous.");
            }
            sawIDAT = YES;
            if (idat.length > kCNDMaximumInputBytes - chunkLength) {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                                   @"PNG compressed data exceeds the processor limit.");
            }
            [idat appendBytes:payload length:chunkLength];
        } else if (CNDChunkNameIs(name, "IEND")) {
            if (!sawIHDR || !sawIDAT || sawIEND || chunkLength != 0) {
                return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                   @"PNG IEND chunk is invalid.");
            }
            sawIEND = YES;
            outInfo->unpaddedLength = offset + 12u;
            NSUInteger trailing = data.length - outInfo->unpaddedLength;
            if (trailing > 0) {
                if (!allowZeroPadding) {
                    return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                       @"PNG contains bytes after IEND.");
                }
                const uint8_t *tail = bytes + outInfo->unpaddedLength;
                for (NSUInteger i = 0; i < trailing; i++) {
                    if (tail[i] != 0) {
                        return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                                           @"PNG padding contains a non-zero byte.");
                    }
                }
                break;
            }
        } else if (CNDChunkNameIs(name, "acTL") || CNDChunkNameIs(name, "fdAT")) {
            return CNDSetError(error, CNDIconThemeImageProcessorErrorUnsupportedPNG,
                               @"Animated PNGs are not accepted as icon assets.");
        }

        if (CNDChunkNameIs(name, "IDAT")) {
            leftIDAT = NO;
        } else if (sawIDAT && !CNDChunkNameIs(name, "IDAT")) {
            leftIDAT = YES;
        }
        offset += 12u + chunkLength;
        if (sawIEND) break;
    }
    if (!sawIHDR || !sawIDAT || !sawIEND || outInfo->unpaddedLength == 0 ||
        idat.length == 0) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                           @"PNG is missing IHDR, IDAT, or IEND.");
    }
    if (outInfo->colorType == 3 && outInfo->paletteCount == 0) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                           @"A palette PNG does not contain a PLTE chunk.");
    }
    if (outInfo->colorType == 3 &&
        outInfo->paletteCount > (1u << outInfo->bitDepth)) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidPNG,
                           @"The PNG palette has more entries than its bit depth permits.");
    }
    *outIDAT = [idat copy];
    return YES;
}

static uint8_t CNDPaeth(uint8_t a, uint8_t b, uint8_t c)
{
    int p = (int)a + (int)b - (int)c;
    int pa = abs(p - (int)a);
    int pb = abs(p - (int)b);
    int pc = abs(p - (int)c);
    if (pa <= pb && pa <= pc) return a;
    if (pb <= pc) return b;
    return c;
}

static BOOL CNDUnfilterRow(const uint8_t *filtered, uint8_t *row,
                           const uint8_t *previous, NSUInteger rowBytes,
                           NSUInteger bytesPerPixel, NSError **error)
{
    uint8_t filter = filtered[0];
    const uint8_t *src = filtered + 1u;
    if (filter > 4u) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorDecode,
                           @"PNG scanline has an invalid filter type.");
    }
    for (NSUInteger i = 0; i < rowBytes; i++) {
        uint8_t left = i >= bytesPerPixel ? row[i - bytesPerPixel] : 0;
        uint8_t up = previous ? previous[i] : 0;
        uint8_t upLeft = previous && i >= bytesPerPixel
            ? previous[i - bytesPerPixel] : 0;
        switch (filter) {
            case 0: row[i] = src[i]; break;
            case 1: row[i] = (uint8_t)(src[i] + left); break;
            case 2: row[i] = (uint8_t)(src[i] + up); break;
            case 3: row[i] = (uint8_t)(src[i] + ((left + up) / 2u)); break;
            case 4: row[i] = (uint8_t)(src[i] + CNDPaeth(left, up, upLeft)); break;
        }
    }
    return YES;
}

static uint8_t CNDScaleSample(uint16_t value, uint8_t depth)
{
    if (depth == 8u) return (uint8_t)value;
    if (depth == 16u) return (uint8_t)(value >> 8);
    uint32_t maxValue = (1u << depth) - 1u;
    return (uint8_t)((value * 255u + maxValue / 2u) / maxValue);
}

static uint16_t CNDReadPackedSample(const uint8_t *row, NSUInteger index,
                                    uint8_t depth)
{
    if (depth == 8u) return row[index];
    if (depth == 16u) return CNDReadBE16(row + index * 2u);
    NSUInteger bit = index * depth;
    uint8_t value = row[bit / 8u];
    NSUInteger shift = 8u - depth - (bit % 8u);
    return (uint16_t)((value >> shift) & ((1u << depth) - 1u));
}

static BOOL CNDApplyGamma(uint8_t *value, uint32_t gammaTimes100000)
{
    if (!value || gammaTimes100000 == 0 || gammaTimes100000 == 45455u) return YES;
    double encoded = (double)*value / 255.0;
    double linear = pow(encoded, (double)gammaTimes100000 / 100000.0);
    double srgb = linear <= 0.0031308
        ? 12.92 * linear
        : 1.055 * pow(linear, 1.0 / 2.4) - 0.055;
    if (srgb < 0.0) srgb = 0.0;
    if (srgb > 1.0) srgb = 1.0;
    *value = (uint8_t)floor(srgb * 255.0 + 0.5);
    return YES;
}

static void CNDApplyColorToSRGB(uint8_t *r, uint8_t *g, uint8_t *b,
                                const CNDPNGInfo *info)
{
    if (info->hasSRGB || info->gammaTimes100000 == 0) return;
    CNDApplyGamma(r, info->gammaTimes100000);
    CNDApplyGamma(g, info->gammaTimes100000);
    CNDApplyGamma(b, info->gammaTimes100000);
}

static void CNDDestroyImage(CNDImage *image)
{
    if (!image) return;
    free(image->rgba);
    image->rgba = NULL;
    image->width = image->height = 0;
}

static BOOL CNDInflateScanlines(NSData *idat, const CNDPNGInfo *info,
                                NSMutableData **outScanlines, NSError **error)
{
    if (idat.length > UINT_MAX || info->expectedInflatedBytes > UINT_MAX) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"PNG zlib stream exceeds the processor limit.");
    }
    NSMutableData *scanlines = [NSMutableData dataWithLength:info->expectedInflatedBytes];
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef *)idat.bytes;
    stream.avail_in = (uInt)idat.length;
    stream.next_out = scanlines.mutableBytes;
    stream.avail_out = (uInt)scanlines.length;
    int rc = inflateInit(&stream);
    if (rc != Z_OK) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorDecode,
                           @"PNG zlib decoder could not be initialized.");
    }
    BOOL complete = NO;
    while (1) {
        rc = inflate(&stream, Z_NO_FLUSH);
        if (rc == Z_STREAM_END) {
            complete = YES;
            break;
        }
        if (rc != Z_OK || stream.avail_out == 0 || stream.avail_in == 0) break;
    }
    NSUInteger totalIn = (NSUInteger)stream.total_in;
    NSUInteger totalOut = (NSUInteger)stream.total_out;
    inflateEnd(&stream);
    if (!complete || totalIn != idat.length || totalOut != info->expectedInflatedBytes) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorDecode,
                           @"PNG compressed data does not completely decode to its scanlines.");
    }
    *outScanlines = scanlines;
    return YES;
}

static BOOL CNDDecodeRowPixels(const uint8_t *row, NSUInteger passWidth,
                               NSUInteger passX, NSUInteger passY,
                               NSUInteger stepX,
                               const CNDPNGInfo *info, CNDImage *image,
                               NSError **error)
{
    NSUInteger bitsPerPixel = 0;
    if (!CNDBitsPerPixel(info, &bitsPerPixel, NULL)) return NO;
    uint8_t depth = info->bitDepth;
    for (NSUInteger x = 0; x < passWidth; x++) {
        NSUInteger imageX = passX + x * stepX;
        NSUInteger imageY = passY;
        if (imageX >= image->width || imageY >= image->height) return NO;
        const uint8_t *pixel = row;
        uint16_t sample = CNDReadPackedSample(pixel, x, depth);
        uint8_t r = 0, g = 0, b = 0, a = 255;
        switch (info->colorType) {
            case 0: {
                uint16_t raw = sample;
                uint8_t gray = CNDScaleSample(raw, depth);
                r = g = b = gray;
                if (info->hasTransparentGray && raw == info->transparentGray) a = 0;
                break;
            }
            case 2: {
                NSUInteger base = depth == 16u ? x * 6u : x * 3u;
                uint16_t rawR = depth == 16u ? CNDReadBE16(row + base) : row[base];
                uint16_t rawG = depth == 16u ? CNDReadBE16(row + base + (depth == 16u ? 2u : 1u))
                                             : row[base + 1u];
                uint16_t rawB = depth == 16u ? CNDReadBE16(row + base + 4u) : row[base + 2u];
                r = CNDScaleSample(rawR, depth);
                g = CNDScaleSample(rawG, depth);
                b = CNDScaleSample(rawB, depth);
                if (info->hasTransparentRGB && rawR == info->transparentRed &&
                    rawG == info->transparentGreen && rawB == info->transparentBlue) a = 0;
                break;
            }
            case 3: {
                if (sample >= info->paletteCount) {
                    return CNDSetError(error, CNDIconThemeImageProcessorErrorDecode,
                                       @"PNG palette index is outside PLTE.");
                }
                NSUInteger paletteOffset = (NSUInteger)sample * 3u;
                r = info->palette[paletteOffset];
                g = info->palette[paletteOffset + 1u];
                b = info->palette[paletteOffset + 2u];
                if (sample < info->paletteAlphaCount) a = info->paletteAlpha[sample];
                break;
            }
            case 4: {
                NSUInteger base = depth == 16u ? x * 4u : x * 2u;
                uint16_t rawGray = depth == 16u ? CNDReadBE16(row + base) : row[base];
                uint16_t rawAlpha = depth == 16u ? CNDReadBE16(row + base + 2u)
                                                 : row[base + 1u];
                r = g = b = CNDScaleSample(rawGray, depth);
                a = CNDScaleSample(rawAlpha, depth);
                break;
            }
            case 6: {
                NSUInteger base = depth == 16u ? x * 8u : x * 4u;
                r = CNDScaleSample(depth == 16u ? CNDReadBE16(row + base) : row[base], depth);
                g = CNDScaleSample(depth == 16u ? CNDReadBE16(row + base + (depth == 16u ? 2u : 1u))
                                                 : row[base + 1u], depth);
                b = CNDScaleSample(depth == 16u ? CNDReadBE16(row + base + 4u) : row[base + 2u], depth);
                a = CNDScaleSample(depth == 16u ? CNDReadBE16(row + base + 6u) : row[base + 3u], depth);
                break;
            }
            default:
                return CNDSetError(error, CNDIconThemeImageProcessorErrorUnsupportedPNG,
                                   @"PNG color type is unsupported.");
        }
        CNDApplyColorToSRGB(&r, &g, &b, info);
        NSUInteger destination = (imageY * image->width + imageX) * 4u;
        image->rgba[destination] = r;
        image->rgba[destination + 1u] = g;
        image->rgba[destination + 2u] = b;
        image->rgba[destination + 3u] = a;
    }
    (void)bitsPerPixel;
    return YES;
}

static BOOL CNDDecodePNG(NSData *data, BOOL allowZeroPadding,
                         CNDImage *outImage, CNDPNGInfo *outInfo,
                         NSError **error)
{
    if (!outImage || !outInfo) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                           @"PNG decoder output arguments are invalid.");
    }
    memset(outImage, 0, sizeof(*outImage));
    CNDPNGInfo info;
    NSData *idat = nil;
    if (!CNDParsePNG(data, allowZeroPadding, &info, &idat, error)) return NO;
    NSUInteger rgbaBytes = 0;
    NSUInteger pixels = 0;
    if (!CNDMultiplySize(info.width, info.height, &pixels) ||
        !CNDMultiplySize(pixels, 4u, &rgbaBytes) ||
        rgbaBytes > kCNDMaximumDecodedBytes) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"Decoded RGBA storage exceeds the processor limit.");
    }
    NSMutableData *scanlines = nil;
    if (!CNDInflateScanlines(idat, &info, &scanlines, error)) return NO;
    uint8_t *rgba = calloc(1u, rgbaBytes);
    if (!rgba) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"Could not allocate bounded RGBA storage.");
    }
    outImage->width = info.width;
    outImage->height = info.height;
    outImage->rgba = rgba;
    const uint8_t *compressedRows = scanlines.bytes;
    NSUInteger compressedOffset = 0;
    NSUInteger bitsPerPixel = 0;
    NSUInteger bytesPerPixel = 0;
    CNDBitsPerPixel(&info, &bitsPerPixel, &bytesPerPixel);

    static const uint8_t startsX[7] = { 0, 4, 0, 2, 0, 1, 0 };
    static const uint8_t startsY[7] = { 0, 0, 4, 0, 2, 0, 1 };
    static const uint8_t stepsX[7]  = { 8, 8, 4, 4, 2, 2, 1 };
    static const uint8_t stepsY[7]  = { 8, 8, 4, 4, 2, 2, 1 };
    NSUInteger passCount = info.interlace == 0 ? 1u : 7u;
    for (NSUInteger pass = 0; pass < passCount; pass++) {
        NSUInteger passWidth = info.interlace == 0 ? info.width : 0;
        NSUInteger passHeight = info.interlace == 0 ? info.height : 0;
        NSUInteger startX = info.interlace == 0 ? 0 : startsX[pass];
        NSUInteger startY = info.interlace == 0 ? 0 : startsY[pass];
        NSUInteger stepX = info.interlace == 0 ? 1 : stepsX[pass];
        NSUInteger stepY = info.interlace == 0 ? 1 : stepsY[pass];
        if (info.interlace != 0) {
            CNDPassDimensions(info.width, info.height, startX, startY,
                              stepX, stepY, &passWidth, &passHeight);
        }
        if (passWidth == 0 || passHeight == 0) continue;
        NSUInteger rowBytes = 0;
        if (!CNDRowBytes(passWidth, bitsPerPixel, &rowBytes)) {
            CNDDestroyImage(outImage);
            return CNDSetError(error, CNDIconThemeImageProcessorErrorDecode,
                               @"PNG row arithmetic overflowed.");
        }
        uint8_t *row = malloc(rowBytes);
        uint8_t *previous = calloc(1u, rowBytes);
        if (!row || !previous) {
            free(row); free(previous); CNDDestroyImage(outImage);
            return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                               @"Could not allocate PNG filter rows.");
        }
        for (NSUInteger y = 0; y < passHeight; y++) {
            NSUInteger rowWithFilter = rowBytes + 1u;
            if (compressedOffset > scanlines.length - rowWithFilter) {
                free(row); free(previous); CNDDestroyImage(outImage);
                return CNDSetError(error, CNDIconThemeImageProcessorErrorDecode,
                                   @"PNG scanline stream ended early.");
            }
            if (!CNDUnfilterRow(compressedRows + compressedOffset, row, previous,
                                rowBytes, bytesPerPixel, error)) {
                free(row); free(previous); CNDDestroyImage(outImage); return NO;
            }
            NSUInteger imageY = startY + y * stepY;
            if (!CNDDecodeRowPixels(row, passWidth, startX, imageY, stepX,
                                    &info, outImage, error)) {
                free(row); free(previous); CNDDestroyImage(outImage); return NO;
            }
            memcpy(previous, row, rowBytes);
            compressedOffset += rowWithFilter;
        }
        free(row); free(previous);
    }
    if (compressedOffset != scanlines.length) {
        CNDDestroyImage(outImage);
        return CNDSetError(error, CNDIconThemeImageProcessorErrorDecode,
                           @"PNG scanline stream has trailing data.");
    }
    info.orientation = info.orientation == 0 ? 1 : info.orientation;
    *outInfo = info;
    return YES;
}

static void CNDOrientedDimensions(const CNDImage *source, uint8_t orientation,
                                  NSUInteger *widthOut, NSUInteger *heightOut)
{
    BOOL swaps = orientation >= 5u && orientation <= 8u;
    if (widthOut) *widthOut = swaps ? source->height : source->width;
    if (heightOut) *heightOut = swaps ? source->width : source->height;
}

/// Maps a pixel in the normalized (EXIF-oriented) image to the source pixel.
static void CNDSourceCoordinateForOriented(NSUInteger x, NSUInteger y,
                                            const CNDImage *source,
                                            uint8_t orientation,
                                            NSUInteger *sourceX,
                                            NSUInteger *sourceY)
{
    NSUInteger sx = x;
    NSUInteger sy = y;
    switch (orientation) {
        case 2: sx = source->width - 1u - x; sy = y; break;
        case 3: sx = source->width - 1u - x; sy = source->height - 1u - y; break;
        case 4: sx = x; sy = source->height - 1u - y; break;
        case 5: sx = y; sy = x; break;
        case 6: sx = y; sy = source->height - 1u - x; break;
        case 7: sx = source->width - 1u - y; sy = source->height - 1u - x; break;
        case 8: sx = source->width - 1u - y; sy = x; break;
        default: break;
    }
    if (sourceX) *sourceX = sx;
    if (sourceY) *sourceY = sy;
}

// The old implementation selected one source pixel for each destination
// pixel.  That is especially visible when an imported theme is larger than
// the installed icon slot: diagonal edges become stair-stepped and thin
// details can disappear entirely.  Keep the working image in straight RGBA,
// but do the interpolation in premultiplied-alpha space.  Interpolating the
// RGB channels independently would pull the RGB values of transparent pixels
// into the visible edge and create a dark/bright fringe around artwork.
typedef struct {
    NSUInteger indices[4];
    double weights[4];
} CNDCubicTaps;

static double CNDCatmullRomWeight(double distance)
{
    // Catmull-Rom (B=0, C=1/2) is a good compromise for small icon artwork:
    // it is sharper than bilinear interpolation without requiring a large
    // support window.  The fixed formula and tap order keep output stable.
    distance = fabs(distance);
    if (distance < 1.0) {
        return 1.5 * distance * distance * distance -
            2.5 * distance * distance + 1.0;
    }
    if (distance < 2.0) {
        return -0.5 * distance * distance * distance +
            2.5 * distance * distance - 4.0 * distance + 2.0;
    }
    return 0.0;
}

static void CNDBuildCubicTaps(NSUInteger sourceLength, NSUInteger targetLength,
                              NSUInteger targetIndex, CNDCubicTaps *outTaps)
{
    if (!outTaps || sourceLength == 0 || targetLength == 0) return;
    double position = ((double)targetIndex + 0.5) *
        (double)sourceLength / (double)targetLength - 0.5;
    long base = (long)floor(position);
    double weightSum = 0.0;
    for (NSUInteger tap = 0; tap < 4u; tap++) {
        long index = base + (long)tap - 1L;
        if (index < 0L) index = 0L;
        if (index >= (long)sourceLength) index = (long)sourceLength - 1L;
        double weight = CNDCatmullRomWeight(position - (double)(base +
                                                                 (long)tap - 1L));
        outTaps->indices[tap] = (NSUInteger)index;
        outTaps->weights[tap] = weight;
        weightSum += weight;
    }
    // Clamping edge taps normally preserves a unit sum, but normalize it so
    // that the boundary remains deterministic even for extreme dimensions.
    if (fabs(weightSum) < 1.0e-12) {
        for (NSUInteger tap = 0; tap < 4u; tap++) outTaps->weights[tap] = 0.0;
        outTaps->indices[1] = MIN(sourceLength - 1u,
                                   (NSUInteger)MAX(0L, base));
        outTaps->weights[1] = 1.0;
    } else {
        for (NSUInteger tap = 0; tap < 4u; tap++) {
            outTaps->weights[tap] /= weightSum;
        }
    }
}

static uint8_t CNDRoundClampedByte(double value)
{
    if (!(value > 0.0)) return 0u;
    if (value >= 255.0) return 255u;
    return (uint8_t)floor(value + 0.5);
}

static void CNDResamplePremultipliedPixel(const CNDImage *source,
                                          uint8_t orientation,
                                          const CNDCubicTaps *xTaps,
                                          const CNDCubicTaps *yTaps,
                                          uint8_t *destination)
{
    double alpha = 0.0;
    double premultiplied[3] = { 0.0, 0.0, 0.0 };
    double weightSum = 0.0;
    for (NSUInteger yTap = 0; yTap < 4u; yTap++) {
        for (NSUInteger xTap = 0; xTap < 4u; xTap++) {
            double weight = xTaps->weights[xTap] * yTaps->weights[yTap];
            NSUInteger orientedX = xTaps->indices[xTap];
            NSUInteger orientedY = yTaps->indices[yTap];
            NSUInteger sourceX = 0;
            NSUInteger sourceY = 0;
            CNDSourceCoordinateForOriented(orientedX, orientedY, source,
                                            orientation, &sourceX, &sourceY);
            const uint8_t *pixel = source->rgba +
                (sourceY * source->width + sourceX) * 4u;
            double pixelAlpha = (double)pixel[3];
            alpha += weight * pixelAlpha;
            for (NSUInteger channel = 0; channel < 3u; channel++) {
                premultiplied[channel] += weight *
                    (double)pixel[channel] * pixelAlpha;
            }
            weightSum += weight;
        }
    }
    if (fabs(weightSum) >= 1.0e-12) {
        alpha /= weightSum;
        for (NSUInteger channel = 0; channel < 3u; channel++) {
            premultiplied[channel] /= weightSum;
        }
    }
    if (!(alpha > 0.5)) {
        // Fully transparent pixels have no visible color.  Clearing RGB here
        // also prevents arbitrary RGB hidden under alpha=0 from surviving a
        // later indexed-PNG conversion.
        memset(destination, 0, 4u);
        return;
    }
    alpha = MAX(0.0, MIN(255.0, alpha));
    destination[3] = CNDRoundClampedByte(alpha);
    if (alpha <= 0.5) {
        memset(destination, 0, 4u);
        return;
    }
    // The common alpha factor cancels when unpremultiplying.  Clamp each
    // channel after interpolation because Catmull-Rom has a small negative
    // lobe that can overshoot a sharp edge.
    for (NSUInteger channel = 0; channel < 3u; channel++) {
        double value = premultiplied[channel] / alpha;
        destination[channel] = CNDRoundClampedByte(value);
    }
}

static BOOL CNDFitImage(const CNDImage *source, uint8_t orientation,
                        NSUInteger targetWidth, NSUInteger targetHeight,
                        CNDImage *outImage, NSUInteger *scaledWidthOut,
                        NSUInteger *scaledHeightOut, NSUInteger *offsetXOut,
                        NSUInteger *offsetYOut, NSError **error)
{
    if (!source || !source->rgba || !outImage || targetWidth == 0 || targetHeight == 0) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                           @"Icon target dimensions or source pixels are invalid.");
    }
    NSUInteger orientedWidth = 0;
    NSUInteger orientedHeight = 0;
    CNDOrientedDimensions(source, orientation, &orientedWidth, &orientedHeight);
    if (orientedWidth == 0 || orientedHeight == 0) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorDecode,
                           @"PNG orientation produced an empty image.");
    }
    NSUInteger lhs = 0;
    NSUInteger rhs = 0;
    if (!CNDMultiplySize(orientedWidth, targetHeight, &lhs) ||
        !CNDMultiplySize(targetWidth, orientedHeight, &rhs)) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"Icon aspect-fit arithmetic overflowed.");
    }
    NSUInteger scaledWidth = 0;
    NSUInteger scaledHeight = 0;
    if (lhs >= rhs) {
        scaledWidth = targetWidth;
        scaledHeight = (NSUInteger)(((uint64_t)orientedHeight * targetWidth) /
                                    orientedWidth);
    } else {
        scaledHeight = targetHeight;
        scaledWidth = (NSUInteger)(((uint64_t)orientedWidth * targetHeight) /
                                   orientedHeight);
    }
    scaledWidth = MAX((NSUInteger)1, MIN(targetWidth, scaledWidth));
    scaledHeight = MAX((NSUInteger)1, MIN(targetHeight, scaledHeight));
    NSUInteger targetPixels = 0;
    NSUInteger targetBytes = 0;
    if (!CNDMultiplySize(targetWidth, targetHeight, &targetPixels) ||
        !CNDMultiplySize(targetPixels, 4u, &targetBytes) ||
        targetPixels > CNDIconThemeImageProcessorMaximumPixels ||
        targetBytes > kCNDMaximumDecodedBytes) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"Icon target canvas exceeds the processor limit.");
    }
    NSUInteger sourcePixels = 0;
    NSUInteger sourceBytes = 0;
    if (!CNDMultiplySize(source->width, source->height, &sourcePixels) ||
        !CNDMultiplySize(sourcePixels, 4u, &sourceBytes) ||
        sourceBytes > kCNDMaximumDecodedBytes ||
        targetBytes > kCNDMaximumDecodedBytes - MIN(sourceBytes, kCNDMaximumDecodedBytes)) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"Source and target RGBA storage exceeds the processor limit.");
    }
    uint8_t *rgba = calloc(1u, targetBytes);
    if (!rgba) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"Could not allocate the target RGBA canvas.");
    }
    outImage->width = targetWidth;
    outImage->height = targetHeight;
    outImage->rgba = rgba;
    NSUInteger offsetX = (targetWidth - scaledWidth) / 2u;
    NSUInteger offsetY = (targetHeight - scaledHeight) / 2u;

    NSUInteger xTapBytes = 0;
    NSUInteger yTapBytes = 0;
    if (!CNDMultiplySize(scaledWidth, sizeof(CNDCubicTaps), &xTapBytes) ||
        !CNDMultiplySize(scaledHeight, sizeof(CNDCubicTaps), &yTapBytes)) {
        CNDDestroyImage(outImage);
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"Icon resampling tap storage arithmetic overflowed.");
    }
    CNDCubicTaps *xTaps = calloc(1u, xTapBytes);
    CNDCubicTaps *yTaps = calloc(1u, yTapBytes);
    if (!xTaps || !yTaps) {
        free(xTaps);
        free(yTaps);
        CNDDestroyImage(outImage);
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"Could not allocate icon resampling taps.");
    }
    for (NSUInteger x = 0; x < scaledWidth; x++) {
        CNDBuildCubicTaps(orientedWidth, scaledWidth, x, &xTaps[x]);
    }
    for (NSUInteger y = 0; y < scaledHeight; y++) {
        CNDBuildCubicTaps(orientedHeight, scaledHeight, y, &yTaps[y]);
    }
    for (NSUInteger y = 0; y < scaledHeight; y++) {
        for (NSUInteger x = 0; x < scaledWidth; x++) {
            NSUInteger targetOffset = ((offsetY + y) * targetWidth + offsetX + x) * 4u;
            CNDResamplePremultipliedPixel(source, orientation, &xTaps[x],
                                          &yTaps[y], rgba + targetOffset);
        }
    }
    free(xTaps);
    free(yTaps);
    if (scaledWidthOut) *scaledWidthOut = scaledWidth;
    if (scaledHeightOut) *scaledHeightOut = scaledHeight;
    if (offsetXOut) *offsetXOut = offsetX;
    if (offsetYOut) *offsetYOut = offsetY;
    return YES;
}

// -------------------------------------------------------------------------
// SHA-256.  Keeping the digest implementation here avoids another linker
// dependency and makes the result usable by a tiny host verifier.

typedef struct {
    uint32_t state[8];
    uint64_t bitCount;
    uint8_t block[64];
    NSUInteger blockLength;
} CNDSHA256;

static const uint32_t kCNDSHA256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t CNDRotl(uint32_t value, uint32_t count)
{
    return (value << count) | (value >> (32u - count));
}

static void CNDSHA256Transform(CNDSHA256 *ctx, const uint8_t *block)
{
    uint32_t w[64];
    for (NSUInteger i = 0; i < 16u; i++) w[i] = CNDReadBE32(block + i * 4u);
    for (NSUInteger i = 16u; i < 64u; i++) {
        uint32_t s0 = CNDRotl(w[i - 15u], 25u) ^ CNDRotl(w[i - 15u], 14u) ^
            (w[i - 15u] >> 3u);
        uint32_t s1 = CNDRotl(w[i - 2u], 15u) ^ CNDRotl(w[i - 2u], 13u) ^
            (w[i - 2u] >> 10u);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (NSUInteger i = 0; i < 64u; i++) {
        uint32_t S1 = CNDRotl(e, 26u) ^ CNDRotl(e, 21u) ^ CNDRotl(e, 7u);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + kCNDSHA256K[i] + w[i];
        uint32_t S0 = CNDRotl(a, 30u) ^ CNDRotl(a, 19u) ^ CNDRotl(a, 10u);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void CNDSHA256Init(CNDSHA256 *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
}

static void CNDSHA256Update(CNDSHA256 *ctx, const uint8_t *bytes, NSUInteger length)
{
    ctx->bitCount += (uint64_t)length * 8u;
    while (length > 0) {
        NSUInteger take = MIN(length, 64u - ctx->blockLength);
        memcpy(ctx->block + ctx->blockLength, bytes, take);
        ctx->blockLength += take;
        bytes += take;
        length -= take;
        if (ctx->blockLength == 64u) {
            CNDSHA256Transform(ctx, ctx->block);
            ctx->blockLength = 0;
        }
    }
}

static void CNDSHA256Final(CNDSHA256 *ctx, uint8_t digest[32])
{
    NSUInteger length = ctx->blockLength;
    ctx->block[length++] = 0x80u;
    if (length > 56u) {
        memset(ctx->block + length, 0, 64u - length);
        CNDSHA256Transform(ctx, ctx->block);
        length = 0;
    }
    memset(ctx->block + length, 0, 56u - length);
    for (NSUInteger i = 0; i < 8u; i++) {
        ctx->block[56u + i] = (uint8_t)(ctx->bitCount >> (56u - i * 8u));
    }
    CNDSHA256Transform(ctx, ctx->block);
    for (NSUInteger i = 0; i < 8u; i++) {
        digest[i * 4u] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4u + 1u] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4u + 2u] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4u + 3u] = (uint8_t)ctx->state[i];
    }
}

static NSString *CNDHash(NSData *data)
{
    CNDSHA256 sha;
    uint8_t digest[32];
    CNDSHA256Init(&sha);
    CNDSHA256Update(&sha, data.bytes, data.length);
    CNDSHA256Final(&sha, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:64u];
    for (NSUInteger i = 0; i < sizeof(digest); i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    return hex;
}

// -------------------------------------------------------------------------
// Canonical PNG encoding.

static void CNDAppendBE32(NSMutableData *data, uint32_t value)
{
    uint8_t bytes[4] = {
        (uint8_t)(value >> 24), (uint8_t)(value >> 16),
        (uint8_t)(value >> 8), (uint8_t)value
    };
    [data appendBytes:bytes length:sizeof(bytes)];
}

static BOOL CNDAppendPNGChunk(NSMutableData *png, const char type[4],
                              const uint8_t *payload, NSUInteger length,
                              NSError **error)
{
    if (length > UINT32_MAX) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorEncode,
                           @"PNG chunk exceeds the format length limit.");
    }
    CNDAppendBE32(png, (uint32_t)length);
    [png appendBytes:type length:4u];
    if (length > 0) [png appendBytes:payload length:length];
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef *)type, 4u);
    if (length > 0) crc = crc32(crc, payload, (uInt)length);
    CNDAppendBE32(png, (uint32_t)crc);
    return YES;
}

static NSData *CNDDeflateWithStrategy(NSData *input, int strategy,
                                      NSError **error)
{
    if (input.length > UINT_MAX) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                    @"PNG scanlines exceed zlib's bounded input size.");
        return nil;
    }
    uLong bound = compressBound((uLong)input.length);
    if (bound > kCNDMaximumDecodedBytes || bound > NSUIntegerMax ||
        bound > UINT_MAX) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                    @"PNG compressed output exceeds the processor limit.");
        return nil;
    }
    NSMutableData *compressed = [NSMutableData dataWithLength:(NSUInteger)bound];
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef *)input.bytes;
    stream.avail_in = (uInt)input.length;
    stream.next_out = compressed.mutableBytes;
    stream.avail_out = (uInt)bound;
    int rc = deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, 15, 8,
                          strategy);
    if (rc != Z_OK) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorEncode,
                    @"PNG zlib encoder could not be initialized.");
        return nil;
    }
    rc = deflate(&stream, Z_FINISH);
    NSUInteger length = (NSUInteger)stream.total_out;
    deflateEnd(&stream);
    if (rc != Z_STREAM_END || length == 0) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorEncode,
                    @"PNG zlib encoder did not finish deterministically.");
        return nil;
    }
    [compressed setLength:length];
    return compressed;
}

static NSData *CNDDeflateDeterministic(NSData *input, NSError **error)
{
    if (!input) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                    @"PNG scanlines are required for compression.");
        return nil;
    }
    // zlib's strategies are deterministic for identical input and version.
    // Selecting the shortest stream preserves that property while avoiding
    // the unnecessarily large output produced by fixed Huffman coding for
    // photographic or anti-aliased icon rows.  The order is a deterministic
    // tie-breaker and keeps the normal strategy preferred when sizes match.
    static const int strategies[] = {
        Z_DEFAULT_STRATEGY, Z_FILTERED, Z_RLE, Z_FIXED
    };
    NSData *best = nil;
    NSError *lastError = nil;
    for (NSUInteger i = 0; i < sizeof(strategies) / sizeof(strategies[0]); i++) {
        NSError *candidateError = nil;
        NSData *candidate = CNDDeflateWithStrategy(input, strategies[i],
                                                    &candidateError);
        if (candidate && (!best || candidate.length < best.length)) {
            best = candidate;
        }
        if (candidateError) lastError = candidateError;
    }
    if (best) return best;
    if (error) {
        *error = lastError ?: [NSError errorWithDomain:CNDIconThemeImageProcessorErrorDomain
                                                   code:CNDIconThemeImageProcessorErrorEncode
                                               userInfo:@{ NSLocalizedDescriptionKey :
                                                               @"PNG zlib encoder could not produce a deterministic stream." }];
    }
    return nil;
}

static uint8_t CNDPNGFilterPredictor(const uint8_t *raw,
                                     const uint8_t *previous,
                                     NSUInteger index, NSUInteger bytesPerPixel,
                                     uint8_t filter)
{
    uint8_t left = index >= bytesPerPixel ? raw[index - bytesPerPixel] : 0u;
    uint8_t up = previous ? previous[index] : 0u;
    uint8_t upLeft = previous && index >= bytesPerPixel
        ? previous[index - bytesPerPixel] : 0u;
    switch (filter) {
        case 1: return left;
        case 2: return up;
        case 3: return (uint8_t)(((NSUInteger)left + (NSUInteger)up) / 2u);
        case 4: return CNDPaeth(left, up, upLeft);
        default: return 0u;
    }
}

static uint64_t CNDPNGFilterRow(const uint8_t *raw, const uint8_t *previous,
                                NSUInteger rowBytes, NSUInteger bytesPerPixel,
                                uint8_t filter, uint8_t *filtered)
{
    uint64_t score = 0u;
    for (NSUInteger i = 0; i < rowBytes; i++) {
        uint8_t predictor = CNDPNGFilterPredictor(raw, previous, i,
                                                  bytesPerPixel, filter);
        uint8_t value = (uint8_t)(raw[i] - predictor);
        filtered[i] = value;
        // PNG's conventional adaptive-filter heuristic measures the signed
        // byte magnitude.  It is cheap, deterministic, and works well for
        // both RGBA and packed indexed rows.
        score += (uint64_t)(value < 128u ? value : 256u - value);
    }
    return score;
}

static NSData *CNDEncodeCanonicalPNG(const CNDImage *image,
                                     const CNDPaletteColor *palette,
                                     NSUInteger paletteCount,
                                     const uint8_t *indices,
                                     NSError **error)
{
    if (!image || !image->rgba || image->width == 0 || image->height == 0) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                    @"Cannot encode an empty RGBA image.");
        return nil;
    }
    BOOL indexed = palette != NULL;
    if (indexed && (paletteCount == 0 || paletteCount > kCNDMaximumPaletteEntries || !indices)) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorEncode,
                    @"Indexed PNG palette arguments are invalid.");
        return nil;
    }
    uint8_t bitDepth = 8u;
    if (indexed) {
        if (paletteCount <= 2u) bitDepth = 1u;
        else if (paletteCount <= 4u) bitDepth = 2u;
        else if (paletteCount <= 16u) bitDepth = 4u;
    }
    NSUInteger bitsPerPixel = indexed ? bitDepth : 32u;
    NSUInteger rowBytes = 0;
    if (!CNDRowBytes(image->width, bitsPerPixel, &rowBytes)) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                    @"PNG output row arithmetic overflowed.");
        return nil;
    }
    NSUInteger rowWithFilter = 0;
    NSUInteger scanlineLength = 0;
    if (!CNDAddSize(rowBytes, 1u, &rowWithFilter) ||
        !CNDMultiplySize(rowWithFilter, image->height, &scanlineLength) ||
        scanlineLength > kCNDMaximumDecodedBytes) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                    @"PNG output scanlines exceed the processor limit.");
        return nil;
    }
    NSMutableData *scanlines = [NSMutableData dataWithLength:scanlineLength];
    uint8_t *out = scanlines.mutableBytes;
    // Keep unfiltered rows separate from the encoded scanlines.  PNG filters
    // are predictors of the original row, not of the previously filtered
    // row.  Two reusable row buffers keep this bounded even for the maximum
    // accepted source dimensions.
    uint8_t *rawRow = calloc(1u, rowBytes);
    uint8_t *previousRow = calloc(1u, rowBytes);
    uint8_t *candidateRow = malloc(rowBytes);
    uint8_t *bestRow = malloc(rowBytes);
    if (!rawRow || !previousRow || !candidateRow || !bestRow) {
        free(rawRow); free(previousRow); free(candidateRow); free(bestRow);
        CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                    @"Could not allocate PNG filter rows.");
        return nil;
    }
    NSUInteger filterBytesPerPixel = MAX((NSUInteger)1u,
                                         (bitsPerPixel + 7u) / 8u);
    for (NSUInteger y = 0; y < image->height; y++) {
        if (!indexed) {
            memcpy(rawRow, image->rgba + y * image->width * 4u, rowBytes);
        } else if (bitDepth == 8u) {
            memcpy(rawRow, indices + y * image->width, rowBytes);
        } else {
            memset(rawRow, 0, rowBytes);
            for (NSUInteger x = 0; x < image->width; x++) {
                NSUInteger bit = x * bitDepth;
                NSUInteger byteOffset = bit / 8u;
                NSUInteger shift = 8u - bitDepth - (bit % 8u);
                rawRow[byteOffset] |=
                    (uint8_t)((indices[y * image->width + x] & ((1u << bitDepth) - 1u)) << shift);
            }
        }

        uint64_t bestScore = UINT64_MAX;
        uint8_t bestFilter = 0u;
        for (uint8_t filter = 0u; filter <= 4u; filter++) {
            uint64_t score = CNDPNGFilterRow(rawRow, previousRow, rowBytes,
                                             filterBytesPerPixel, filter,
                                             candidateRow);
            if (score < bestScore) {
                bestScore = score;
                bestFilter = filter;
                memcpy(bestRow, candidateRow, rowBytes);
            }
        }
        NSUInteger rowOffset = y * rowWithFilter;
        out[rowOffset] = bestFilter;
        memcpy(out + rowOffset + 1u, bestRow, rowBytes);

        uint8_t *swap = previousRow;
        previousRow = rawRow;
        rawRow = swap;
    }
    free(rawRow); free(previousRow); free(candidateRow); free(bestRow);
    NSData *compressed = CNDDeflateDeterministic(scanlines, error);
    if (!compressed) return nil;

    static const uint8_t signature[8] = {
        0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
    };
    NSMutableData *png = [NSMutableData dataWithCapacity:
                          8u + 25u + (indexed ? 12u + paletteCount * 3u + 12u + paletteCount : 12u) +
                          compressed.length + 12u];
    [png appendBytes:signature length:sizeof(signature)];
    uint8_t ihdr[13] = { 0 };
    ihdr[0] = (uint8_t)(image->width >> 24);
    ihdr[1] = (uint8_t)(image->width >> 16);
    ihdr[2] = (uint8_t)(image->width >> 8);
    ihdr[3] = (uint8_t)image->width;
    ihdr[4] = (uint8_t)(image->height >> 24);
    ihdr[5] = (uint8_t)(image->height >> 16);
    ihdr[6] = (uint8_t)(image->height >> 8);
    ihdr[7] = (uint8_t)image->height;
    ihdr[8] = bitDepth;
    ihdr[9] = indexed ? 3u : 6u;
    if (!CNDAppendPNGChunk(png, "IHDR", ihdr, sizeof(ihdr), error)) return nil;
    uint8_t srgbIntent = 0u;
    if (!CNDAppendPNGChunk(png, "sRGB", &srgbIntent, 1u, error)) return nil;
    NSMutableData *plte = nil;
    NSMutableData *trns = nil;
    if (indexed) {
        plte = [NSMutableData dataWithLength:paletteCount * 3u];
        trns = [NSMutableData dataWithLength:paletteCount];
        uint8_t *plteBytes = plte.mutableBytes;
        uint8_t *trnsBytes = trns.mutableBytes;
        for (NSUInteger i = 0; i < paletteCount; i++) {
            plteBytes[i * 3u] = palette[i].r;
            plteBytes[i * 3u + 1u] = palette[i].g;
            plteBytes[i * 3u + 2u] = palette[i].b;
            trnsBytes[i] = palette[i].a;
        }
        if (!CNDAppendPNGChunk(png, "PLTE", plte.bytes, plte.length, error) ||
            !CNDAppendPNGChunk(png, "tRNS", trns.bytes, trns.length, error)) return nil;
    }
    if (!CNDAppendPNGChunk(png, "IDAT", compressed.bytes, compressed.length, error) ||
        !CNDAppendPNGChunk(png, "IEND", NULL, 0u, error)) return nil;
    return png;
}

static uint8_t CNDPremultipliedByte(uint8_t component, uint8_t alpha)
{
    return (uint8_t)(((NSUInteger)component * (NSUInteger)alpha + 127u) / 255u);
}

static NSUInteger CNDHistogramBinForPixel(const uint8_t *pixel)
{
    uint8_t premultiplied[3] = {
        CNDPremultipliedByte(pixel[0], pixel[3]),
        CNDPremultipliedByte(pixel[1], pixel[3]),
        CNDPremultipliedByte(pixel[2], pixel[3]),
    };
    NSUInteger red = MIN(kCNDHistogramRGBBins - 1u,
                         ((NSUInteger)premultiplied[0] * kCNDHistogramRGBBins) / 256u);
    NSUInteger green = MIN(kCNDHistogramRGBBins - 1u,
                           ((NSUInteger)premultiplied[1] * kCNDHistogramRGBBins) / 256u);
    NSUInteger blue = MIN(kCNDHistogramRGBBins - 1u,
                          ((NSUInteger)premultiplied[2] * kCNDHistogramRGBBins) / 256u);
    NSUInteger alpha = MIN(kCNDHistogramAlphaBins - 1u,
                           ((NSUInteger)pixel[3] * kCNDHistogramAlphaBins) / 256u);
    return (((red * kCNDHistogramRGBBins + green) * kCNDHistogramRGBBins + blue) *
            kCNDHistogramAlphaBins) + alpha;
}

static uint8_t CNDRoundedRatio(uint64_t numerator, uint64_t denominator)
{
    if (denominator == 0u) return 0u;
    uint64_t rounded = (numerator + denominator / 2u) / denominator;
    return (uint8_t)MIN((uint64_t)255u, rounded);
}

static void CNDSetHistogramEntryRepresentative(CNDColorEntry *entry)
{
    if (!entry || entry->count == 0u) return;
    uint8_t alpha = CNDRoundedRatio(entry->sumAlpha, entry->count);
    entry->a = alpha;
    entry->r = entry->g = entry->b = 0u;
    for (NSUInteger channel = 0; channel < 3u; channel++) {
        uint8_t premultiplied = CNDRoundedRatio(
            entry->sumPremultiplied[channel], entry->count);
        entry->premultiplied[channel] = premultiplied;
        // RGB below alpha=0 has no visual meaning and can create fringes in
        // indexed PNGs.  Canonicalize it to the transparent black value.
        if (alpha != 0u) {
            uint64_t straight = ((uint64_t)premultiplied * 255u + alpha / 2u) / alpha;
            uint8_t value = (uint8_t)MIN((uint64_t)255u, straight);
            if (channel == 0u) entry->r = value;
            else if (channel == 1u) entry->g = value;
            else entry->b = value;
        }
    }
}

static BOOL CNDBuildColorHistogram(const CNDImage *image,
                                   NSUInteger paletteLimit,
                                   CNDColorEntry **entriesOut,
                                   NSUInteger *entryCountOut,
                                   BOOL *overflowOut)
{
    (void)paletteLimit;
    if (!image || !image->rgba || !entriesOut || !entryCountOut ||
        !overflowOut) return NO;

    // Every source pixel contributes to exactly one bounded bin.  This is a
    // dense table rather than an early-exit exact-colour hash: no part of the
    // image is silently discarded when a large source contains more colours
    // than the requested output palette.
    CNDColorEntry *entries = calloc(kCNDHistogramBinCount, sizeof(*entries));
    if (!entries) return NO;
    NSUInteger pixelCount = image->width * image->height;
    for (NSUInteger i = 0; i < pixelCount; i++) {
        const uint8_t *pixel = image->rgba + i * 4u;
        NSUInteger bin = CNDHistogramBinForPixel(pixel);
        CNDColorEntry *entry = &entries[bin];
        if (entry->count == 0u) entry->firstPixel = (uint32_t)MIN(i, UINT32_MAX);
        if (entry->count != UINT64_MAX) entry->count++;
        entry->sumAlpha += pixel[3];
        entry->sumPremultiplied[0] += CNDPremultipliedByte(pixel[0], pixel[3]);
        entry->sumPremultiplied[1] += CNDPremultipliedByte(pixel[1], pixel[3]);
        entry->sumPremultiplied[2] += CNDPremultipliedByte(pixel[2], pixel[3]);
    }

    NSUInteger entryCount = 0u;
    for (NSUInteger bin = 0; bin < kCNDHistogramBinCount; bin++) {
        if (entries[bin].count == 0u) continue;
        CNDSetHistogramEntryRepresentative(&entries[bin]);
        if (entryCount != bin) entries[entryCount] = entries[bin];
        entryCount++;
    }
    *entriesOut = entries;
    *entryCountOut = entryCount;
    // Fixed binning is bounded but never drops a pixel, so there is no
    // overflow/truncation condition for callers to special-case.
    *overflowOut = NO;
    return YES;
}

static int CNDColorComponent(const CNDColorEntry *entry, NSUInteger channel)
{
    switch (channel) {
        case 0: return entry->premultiplied[0];
        case 1: return entry->premultiplied[1];
        case 2: return entry->premultiplied[2];
        default: return entry->a;
    }
}

static void CNDUpdateBoxBounds(CNDColorBox *box, const CNDColorEntry *entries)
{
    for (NSUInteger channel = 0; channel < 4u; channel++) {
        box->minChannel[channel] = 255u;
        box->maxChannel[channel] = 0u;
    }
    box->weight = 0;
    for (NSUInteger i = box->start; i < box->start + box->count; i++) {
        const CNDColorEntry *entry = &entries[box->indices[i]];
        for (NSUInteger channel = 0; channel < 4u; channel++) {
            uint8_t value = (uint8_t)CNDColorComponent(entry, channel);
            if (value < box->minChannel[channel]) box->minChannel[channel] = value;
            if (value > box->maxChannel[channel]) box->maxChannel[channel] = value;
        }
        if (UINT64_MAX - box->weight < entry->count) box->weight = UINT64_MAX;
        else box->weight += entry->count;
    }
}

static BOOL CNDEntryIndexComesAfter(NSUInteger lhsIndex, NSUInteger rhsIndex,
                                    const CNDColorEntry *entries,
                                    NSUInteger channel)
{
    int lhs = CNDColorComponent(&entries[lhsIndex], channel);
    int rhs = CNDColorComponent(&entries[rhsIndex], channel);
    if (lhs != rhs) return lhs > rhs;
    // A total tie-break order makes the merge sort independent of allocator
    // layout and keeps palette hashes stable for identical inputs.
    for (NSUInteger tie = 0; tie < 4u; tie++) {
        lhs = CNDColorComponent(&entries[lhsIndex], tie);
        rhs = CNDColorComponent(&entries[rhsIndex], tie);
        if (lhs != rhs) return lhs > rhs;
    }
    if (entries[lhsIndex].firstPixel != entries[rhsIndex].firstPixel) {
        return entries[lhsIndex].firstPixel > entries[rhsIndex].firstPixel;
    }
    return lhsIndex > rhsIndex;
}

static void CNDSortBox(CNDColorBox *box, const CNDColorEntry *entries,
                       NSUInteger channel)
{
    if (!box || box->count < 2u) return;
    NSUInteger *scratch = malloc(box->count * sizeof(*scratch));
    if (!scratch) {
        // The normal bounded histogram path has enough room for this small
        // scratch allocation.  Keep a deterministic insertion-sort fallback
        // for an unusually constrained process instead of failing a batch.
        for (NSUInteger i = box->start + 1u; i < box->start + box->count; i++) {
            NSUInteger value = box->indices[i];
            NSUInteger j = i;
            while (j > box->start &&
                   CNDEntryIndexComesAfter(box->indices[j - 1u], value,
                                           entries, channel)) {
                box->indices[j] = box->indices[j - 1u];
                j--;
            }
            box->indices[j] = value;
        }
        return;
    }

    NSUInteger width = 1u;
    NSUInteger end = box->start + box->count;
    while (width < box->count) {
        for (NSUInteger left = box->start; left < end; left += width * 2u) {
            NSUInteger middle = MIN(left + width, end);
            NSUInteger right = MIN(middle + width, end);
            NSUInteger i = left;
            NSUInteger j = middle;
            NSUInteger out = left - box->start;
            while (i < middle || j < right) {
                if (j >= right ||
                    (i < middle && !CNDEntryIndexComesAfter(
                        box->indices[i], box->indices[j], entries, channel))) {
                    scratch[out++] = box->indices[i++];
                } else {
                    scratch[out++] = box->indices[j++];
                }
            }
        }
        memcpy(box->indices + box->start, scratch, box->count * sizeof(*scratch));
        if (width > box->count / 2u) break;
        width *= 2u;
    }
    free(scratch);
}

static NSUInteger CNDChooseSplitChannel(const CNDColorBox *box)
{
    NSUInteger channel = 0;
    NSUInteger bestRange = 0;
    for (NSUInteger i = 0; i < 4u; i++) {
        NSUInteger range = (NSUInteger)box->maxChannel[i] - box->minChannel[i];
        // Alpha gets a small tie-breaking preference so transparent edges do
        // not silently become opaque when the color budget is tight.
        if (range > bestRange || (range == bestRange && i == 3u)) {
            bestRange = range;
            channel = i;
        }
    }
    return channel;
}

static BOOL CNDBoxCanSplit(const CNDColorBox *box)
{
    if (box->count < 2u) return NO;
    for (NSUInteger i = 0; i < 4u; i++) {
        if (box->maxChannel[i] != box->minChannel[i]) return YES;
    }
    return YES;
}

static NSUInteger CNDBoxSplitPosition(const CNDColorBox *box,
                                      const CNDColorEntry *entries)
{
    uint64_t target = box->weight / 2u;
    uint64_t running = 0;
    NSUInteger split = box->start + 1u;
    for (NSUInteger i = box->start; i < box->start + box->count - 1u; i++) {
        running += entries[box->indices[i]].count;
        if (running >= target) {
            split = i + 1u;
            break;
        }
    }
    if (split <= box->start) split = box->start + 1u;
    if (split >= box->start + box->count) split = box->start + box->count - 1u;
    return split;
}

static void CNDPalettePremultiplied(const CNDPaletteColor *color,
                                    uint8_t premultiplied[4])
{
    premultiplied[0] = CNDPremultipliedByte(color->r, color->a);
    premultiplied[1] = CNDPremultipliedByte(color->g, color->a);
    premultiplied[2] = CNDPremultipliedByte(color->b, color->a);
    premultiplied[3] = color->a;
}

static uint64_t CNDPremultipliedColorDistance(const uint8_t premultipliedSource[4],
                                              const CNDPaletteColor *palette)
{
    uint8_t palettePremultiplied[4];
    CNDPalettePremultiplied(palette, palettePremultiplied);
    // Integer luma weights keep green detail from being treated as cheaply as
    // blue while the alpha term prevents translucent edges from collapsing
    // into opaque colours.  The comparison is in premultiplied space, so RGB
    // hidden under transparent pixels contributes no error.
    static const uint32_t weights[4] = { 3u, 6u, 1u, 4u };
    uint64_t distance = 0u;
    for (NSUInteger channel = 0; channel < 4u; channel++) {
        int delta = (int)premultipliedSource[channel] -
            (int)palettePremultiplied[channel];
        distance += (uint64_t)(delta * delta) * weights[channel];
    }
    return distance;
}

static NSUInteger CNDNearestPaletteIndex(const uint8_t source[4],
                                         const CNDPaletteColor *palette,
                                         NSUInteger paletteCount,
                                         BOOL requireTransparent)
{
    NSUInteger best = NSNotFound;
    uint64_t bestDistance = UINT64_MAX;
    for (NSUInteger index = 0; index < paletteCount; index++) {
        if (requireTransparent && palette[index].a != 0u) continue;
        uint64_t distance = CNDPremultipliedColorDistance(source, &palette[index]);
        if (best == NSNotFound || distance < bestDistance) {
            best = index;
            bestDistance = distance;
        }
    }
    // A palette generated from a transparent source always gets a transparent
    // black entry below.  Keep a defensive fallback for malformed callers.
    if (best == NSNotFound) {
        best = 0u;
        bestDistance = UINT64_MAX;
        for (NSUInteger index = 0; index < paletteCount; index++) {
            uint64_t distance = CNDPremultipliedColorDistance(source, &palette[index]);
            if (index == 0u || distance < bestDistance) {
                best = index;
                bestDistance = distance;
            }
        }
    }
    return best;
}

static void CNDPaletteColorForBox(const CNDColorBox *box,
                                  const CNDColorEntry *entries,
                                  CNDPaletteColor *outColor)
{
    uint64_t sumPremultiplied[3] = { 0u, 0u, 0u };
    uint64_t sumAlpha = 0u;
    for (NSUInteger index = box->start; index < box->start + box->count; index++) {
        const CNDColorEntry *entry = &entries[box->indices[index]];
        for (NSUInteger channel = 0; channel < 3u; channel++) {
            sumPremultiplied[channel] +=
                (uint64_t)entry->premultiplied[channel] * entry->count;
        }
        sumAlpha += (uint64_t)entry->a * entry->count;
    }
    uint8_t alpha = CNDRoundedRatio(sumAlpha, MAX((uint64_t)1u, box->weight));
    outColor->a = alpha;
    outColor->r = outColor->g = outColor->b = 0u;
    for (NSUInteger channel = 0; channel < 3u; channel++) {
        uint8_t premultiplied = CNDRoundedRatio(
            sumPremultiplied[channel], MAX((uint64_t)1u, box->weight));
        if (alpha == 0u) continue;
        uint64_t straight = ((uint64_t)premultiplied * 255u + alpha / 2u) / alpha;
        uint8_t value = (uint8_t)MIN((uint64_t)255u, straight);
        if (channel == 0u) outColor->r = value;
        else if (channel == 1u) outColor->g = value;
        else outColor->b = value;
    }
}

static BOOL CNDBuildDitheredIndices(const CNDImage *image,
                                    const CNDPaletteColor *palette,
                                    NSUInteger paletteCount,
                                    BOOL dither,
                                    uint8_t *indices,
                                    NSMutableData **expectedOut)
{
    if (!image || !image->rgba || !palette || paletteCount == 0u || !indices ||
        !expectedOut) return NO;
    NSUInteger pixelCount = image->width * image->height;
    NSUInteger rowCells = (image->width + 2u) * 4u;
    double *currentError = calloc(rowCells, sizeof(*currentError));
    double *nextError = calloc(rowCells, sizeof(*nextError));
    if (!currentError || !nextError) {
        free(currentError); free(nextError);
        return NO;
    }

    for (NSUInteger y = 0; y < image->height; y++) {
        memset(nextError, 0, rowCells * sizeof(*nextError));
        BOOL reverse = dither && ((y & 1u) != 0u);
        for (NSUInteger step = 0; step < image->width; step++) {
            NSUInteger x = reverse ? image->width - 1u - step : step;
            NSUInteger pixelIndex = y * image->width + x;
            const uint8_t *source = image->rgba + pixelIndex * 4u;
            NSUInteger cell = (x + 1u) * 4u;
            uint8_t adjusted[4];
            BOOL transparent = source[3] == 0u;
            for (NSUInteger channel = 0; channel < 4u; channel++) {
                uint8_t sourceValue = channel < 3u
                    ? CNDPremultipliedByte(source[channel], source[3])
                    : source[3];
                double value = transparent ? 0.0 :
                    (double)sourceValue + currentError[cell + channel];
                if (!(value > 0.0)) value = 0.0;
                if (value > 255.0) value = 255.0;
                adjusted[channel] = CNDRoundClampedByte(value);
            }
            NSUInteger paletteIndex = CNDNearestPaletteIndex(
                adjusted, palette, paletteCount, transparent);
            indices[pixelIndex] = (uint8_t)paletteIndex;

            if (dither && !transparent) {
                uint8_t palettePremultiplied[4];
                CNDPalettePremultiplied(&palette[paletteIndex], palettePremultiplied);
                double error[4];
                for (NSUInteger channel = 0; channel < 4u; channel++) {
                    error[channel] = (double)adjusted[channel] -
                        (double)palettePremultiplied[channel];
                }
                NSInteger direction = reverse ? -1 : 1;
                NSInteger same = (NSInteger)cell + direction * 4;
                NSInteger downLeft = (NSInteger)cell - direction * 4;
                NSInteger down = (NSInteger)cell;
                NSInteger downRight = (NSInteger)cell + direction * 4;
                if (same >= 0 && (NSUInteger)same < rowCells) {
                    for (NSUInteger channel = 0; channel < 4u; channel++) {
                        currentError[same + channel] += error[channel] * (7.0 / 16.0);
                    }
                }
                if (downLeft >= 0 && (NSUInteger)downLeft < rowCells) {
                    for (NSUInteger channel = 0; channel < 4u; channel++) {
                        nextError[downLeft + channel] += error[channel] * (3.0 / 16.0);
                    }
                }
                for (NSUInteger channel = 0; channel < 4u; channel++) {
                    nextError[down + channel] += error[channel] * (5.0 / 16.0);
                }
                if (downRight >= 0 && (NSUInteger)downRight < rowCells) {
                    for (NSUInteger channel = 0; channel < 4u; channel++) {
                        nextError[downRight + channel] += error[channel] * (1.0 / 16.0);
                    }
                }
            } else {
                // Do not allow error from a visible edge to turn transparent
                // padding into a nonzero-alpha pixel.  Clearing the current
                // cell also prevents a transparent run from leaking error to
                // a later visible region.
                memset(currentError + cell, 0, 4u * sizeof(*currentError));
            }
        }
        double *swap = currentError;
        currentError = nextError;
        nextError = swap;
    }
    free(currentError);
    free(nextError);

    NSMutableData *expected = [NSMutableData dataWithLength:pixelCount * 4u];
    uint8_t *expectedBytes = expected.mutableBytes;
    for (NSUInteger i = 0; i < pixelCount; i++) {
        CNDPaletteColor color = palette[indices[i]];
        expectedBytes[i * 4u] = color.r;
        expectedBytes[i * 4u + 1u] = color.g;
        expectedBytes[i * 4u + 2u] = color.b;
        expectedBytes[i * 4u + 3u] = color.a;
    }
    *expectedOut = expected;
    return YES;
}

static BOOL CNDBuildPalette(const CNDImage *image, NSUInteger paletteLimit,
                            CNDPaletteColor **paletteOut,
                            NSUInteger *paletteCountOut,
                            uint8_t **indicesOut,
                            NSData **expectedRGBAOut,
                            NSArray **paletteArrayOut)
{
    NSMutableData *expected = nil;
    NSMutableArray *array = nil;
    CNDColorEntry *entries = NULL;
    NSUInteger entryCount = 0;
    BOOL overflow = NO;
    if (paletteLimit == 0) return NO;
    if (!CNDBuildColorHistogram(image, paletteLimit, &entries, &entryCount, &overflow) ||
        entryCount == 0) {
        free(entries);
        return NO;
    }
    (void)overflow;
    NSUInteger histogramEntryCount = entryCount;
    // Histogram binning already accounts for every pixel.  Even when the
    // number of occupied bins is below the output limit, use the same
    // premultiplied box/nearest-colour path so alpha handling and palette
    // ordering do not depend on an early-colour special case.
    NSUInteger indexCount = image->width * image->height;
    CNDPaletteColor *palette = calloc(paletteLimit, sizeof(*palette));
    uint8_t *indices = malloc(indexCount);
    NSUInteger *ordered = NULL;
    CNDColorBox *boxes = NULL;
    NSUInteger boxCount = 0;
    if (!palette || !indices) goto failed;
    ordered = malloc(entryCount * sizeof(*ordered));
    boxes = calloc(paletteLimit, sizeof(*boxes));
    if (!ordered || !boxes) goto failed;
    for (NSUInteger i = 0; i < entryCount; i++) ordered[i] = i;
    boxes[0].indices = ordered;
    boxes[0].start = 0;
    boxes[0].count = entryCount;
    CNDUpdateBoxBounds(&boxes[0], entries);
    boxCount = 1;
    while (boxCount < paletteLimit) {
        NSUInteger selected = NSNotFound;
        uint64_t bestScore = 0;
        for (NSUInteger i = 0; i < boxCount; i++) {
            if (!CNDBoxCanSplit(&boxes[i])) continue;
            NSUInteger range = 0;
            for (NSUInteger channel = 0; channel < 4u; channel++) {
                range = MAX(range, (NSUInteger)boxes[i].maxChannel[channel] -
                                  boxes[i].minChannel[channel]);
            }
            uint64_t score = (uint64_t)range * MAX((uint64_t)1u, boxes[i].weight);
            if (selected == NSNotFound || score > bestScore) {
                selected = i; bestScore = score;
            }
        }
        if (selected == NSNotFound) break;
        CNDColorBox *box = &boxes[selected];
        NSUInteger channel = CNDChooseSplitChannel(box);
        CNDSortBox(box, entries, channel);
        NSUInteger split = CNDBoxSplitPosition(box, entries);
        CNDColorBox right = *box;
        right.start = split;
        right.count = box->start + box->count - split;
        box->count = split - box->start;
        CNDUpdateBoxBounds(box, entries);
        CNDUpdateBoxBounds(&right, entries);
        boxes[boxCount++] = right;
    }
    for (NSUInteger i = 0; i < boxCount; i++) {
        CNDPaletteColor color;
        CNDPaletteColorForBox(&boxes[i], entries, &color);
        palette[i] = color;
    }
    entryCount = boxCount;

    BOOL hasTransparentPixel = NO;
    for (NSUInteger i = 0; i < indexCount; i++) {
        if (image->rgba[i * 4u + 3u] == 0u) {
            hasTransparentPixel = YES;
            break;
        }
    }
    if (hasTransparentPixel) {
        BOOL hasTransparentPalette = NO;
        for (NSUInteger i = 0; i < entryCount; i++) {
            if (palette[i].a == 0u) {
                palette[i].r = palette[i].g = palette[i].b = 0u;
                hasTransparentPalette = YES;
                break;
            }
        }
        if (!hasTransparentPalette) {
            // Keep one canonical transparent-black slot so transparent
            // padding remains byte-stable even when its area is small.
            palette[entryCount - 1u] = (CNDPaletteColor){ 0u, 0u, 0u, 0u };
        }
    }

    BOOL dither = histogramEntryCount > entryCount;
    if (!CNDBuildDitheredIndices(image, palette, entryCount, dither, indices, &expected)) {
        goto failed;
    }
    array = [NSMutableArray arrayWithCapacity:entryCount];
    for (NSUInteger i = 0; i < entryCount; i++) {
        [array addObject:@{ @"r": @(palette[i].r), @"g": @(palette[i].g),
                            @"b": @(palette[i].b), @"a": @(palette[i].a) }];
    }
    free(entries); free(ordered); free(boxes);
    *paletteOut = palette;
    *paletteCountOut = entryCount;
    *indicesOut = indices;
    *expectedRGBAOut = expected;
    *paletteArrayOut = array;
    return YES;

failed:
    free(entries); free(palette); free(indices); free(ordered); free(boxes);
    return NO;
}

static NSData *CNDDataFromRGBA(const CNDImage *image)
{
    NSUInteger bytes = 0;
    if (!image || !CNDMultiplySize(image->width, image->height, &bytes) ||
        !CNDMultiplySize(bytes, 4u, &bytes)) return nil;
    return [NSData dataWithBytes:image->rgba length:bytes];
}

/* Keep alpha diagnostics separate from the boolean "has an alpha channel"
 * check.  A PNG may advertise an alpha-capable colour model while every
 * decoded pixel is opaque, and a palette conversion can accidentally lose
 * either the fully-transparent padding or the partially-transparent edge.
 * These counts are cheap at the already-decoded verification point and make
 * it possible to distinguish a processor loss from later IconServices
 * compositing. */
static NSDictionary *CNDAlphaMetrics(NSData *rgba)
{
    if (![rgba isKindOfClass:NSData.class] || rgba.length < 4u ||
        (rgba.length % 4u) != 0u) {
        return @{ @"pixelCount": @0,
                  @"transparentPixelCount": @0,
                  @"partialAlphaPixelCount": @0,
                  @"opaquePixelCount": @0,
                  @"hasTransparentPixels": @NO,
                  @"hasPartialAlpha": @NO,
                  @"hasNonOpaquePixels": @NO,
                  @"minAlpha": @0,
                  @"maxAlpha": @0 };
    }
    const uint8_t *bytes = rgba.bytes;
    NSUInteger count = rgba.length / 4u;
    NSUInteger transparent = 0u;
    NSUInteger partial = 0u;
    NSUInteger opaque = 0u;
    uint8_t minimum = 255u;
    uint8_t maximum = 0u;
    for (NSUInteger index = 0u; index < count; index++) {
        uint8_t alpha = bytes[index * 4u + 3u];
        minimum = MIN(minimum, alpha);
        maximum = MAX(maximum, alpha);
        if (alpha == 0u) transparent++;
        else if (alpha == 255u) opaque++;
        else partial++;
    }
    return @{
        @"pixelCount": @(count),
        @"transparentPixelCount": @(transparent),
        @"partialAlphaPixelCount": @(partial),
        @"opaquePixelCount": @(opaque),
        @"hasTransparentPixels": @(transparent > 0u),
        @"hasPartialAlpha": @(partial > 0u),
        @"hasNonOpaquePixels": @((transparent + partial) > 0u),
        @"minAlpha": @(minimum),
        @"maxAlpha": @(maximum),
    };
}

static NSData *CNDPaddedData(NSData *unpadded, NSUInteger capacity, NSError **error)
{
    if (!unpadded) return nil;
    if (capacity == 0u) return [unpadded copy];
    if (unpadded.length > capacity) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorIconDoesNotFit,
                    [NSString stringWithFormat:
                     @"icon-fit: canonical PNG is %lu bytes but the slot holds %lu bytes",
                     (unsigned long)unpadded.length, (unsigned long)capacity]);
        return nil;
    }
    NSMutableData *padded = [NSMutableData dataWithLength:capacity];
    memcpy(padded.mutableBytes, unpadded.bytes, unpadded.length);
    return padded;
}

static NSDictionary *CNDVerifyCandidate(NSData *unpadded,
                                        NSData *expectedRGBA,
                                        NSData *targetRGBA,
                                        NSString *mode,
                                        NSUInteger paletteLimit,
                                        NSUInteger paletteCount,
                                        NSArray *palette,
                                        NSUInteger targetWidth,
                                        NSUInteger targetHeight,
                                        NSUInteger capacity,
                                        NSUInteger sourceWidth,
                                        NSUInteger sourceHeight,
                                        NSUInteger orientedWidth,
                                        NSUInteger orientedHeight,
                                        NSUInteger scaledWidth,
                                        NSUInteger scaledHeight,
                                        NSUInteger offsetX,
                                        NSUInteger offsetY,
                                        uint8_t orientation,
                                        NSError **error)
{
    NSData *padded = CNDPaddedData(unpadded, capacity, error);
    if (!padded) return nil;
    CNDImage decoded = { 0 };
    CNDPNGInfo decodedInfo;
    if (!CNDDecodePNG(padded, capacity != 0u, &decoded, &decodedInfo, error)) return nil;
    BOOL dimensionsOK = decoded.width == targetWidth && decoded.height == targetHeight;
    NSUInteger expectedBytes = 0;
    BOOL expectedSizeOK = CNDMultiplySize(targetWidth, targetHeight, &expectedBytes) &&
                           CNDMultiplySize(expectedBytes, 4u, &expectedBytes) &&
                           expectedRGBA.length == expectedBytes;
    BOOL pixelsOK = dimensionsOK && expectedSizeOK &&
                    memcmp(decoded.rgba, expectedRGBA.bytes, expectedBytes) == 0;
    NSData *decodedRGBA = [NSData dataWithBytes:decoded.rgba
                                         length:expectedSizeOK ? expectedBytes : 0u];
    NSDictionary *sourceAlphaMetrics = CNDAlphaMetrics(targetRGBA);
    NSDictionary *expectedAlphaMetrics = CNDAlphaMetrics(expectedRGBA);
    NSDictionary *decodedAlphaMetrics = CNDAlphaMetrics(decodedRGBA);
    BOOL sourceHasTransparent = [sourceAlphaMetrics[ @"hasTransparentPixels" ] boolValue];
    BOOL sourceHasPartial = [sourceAlphaMetrics[ @"hasPartialAlpha" ] boolValue];
    BOOL decodedHasTransparent = [decodedAlphaMetrics[ @"hasTransparentPixels" ] boolValue];
    BOOL decodedHasPartial = [decodedAlphaMetrics[ @"hasPartialAlpha" ] boolValue];
    /* Quantization may change individual alpha values, but it must not erase
     * the alpha class that was present in the rendered target.  In
     * particular, preserving only an alpha-capable PNG header is not enough
     * for transparent icon artwork. */
    BOOL alphaOK = (!sourceHasTransparent || decodedHasTransparent) &&
                   (!sourceHasPartial || decodedHasPartial);
    NSString *decodedHash = nil;
    if (dimensionsOK && expectedSizeOK && pixelsOK && alphaOK) {
        decodedHash = CNDHash(decodedRGBA);
    }
    CNDDestroyImage(&decoded);
    if (!dimensionsOK || !expectedSizeOK || !pixelsOK || !alphaOK) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorDecode,
                    @"staged PNG failed exact dimensions, complete decode, or alpha verification");
        return nil;
    }
    NSString *unpaddedHash = CNDHash(unpadded);
    NSString *paddedHash = CNDHash(padded);
    NSMutableDictionary *result = [NSMutableDictionary dictionaryWithDictionary:@{
        @"mode": mode ?: @"rgba",
        @"encoding": mode ?: @"rgba",
        @"palette": palette ?: @[],
        @"paletteCount": @(paletteCount),
        @"paletteLimit": @(paletteLimit),
        @"unpaddedBytes": unpadded,
        @"paddedBytes": padded,
        @"bytes": padded,
        @"unpaddedHash": unpaddedHash,
        @"paddedHash": paddedHash,
        @"unpadHash": unpaddedHash,
        @"padHash": paddedHash,
        @"sourceWidth": @(sourceWidth),
        @"sourceHeight": @(sourceHeight),
        @"sourceDimensions": @{ @"width": @(sourceWidth), @"height": @(sourceHeight) },
        @"orientedWidth": @(orientedWidth),
        @"orientedHeight": @(orientedHeight),
        @"orientedDimensions": @{ @"width": @(orientedWidth), @"height": @(orientedHeight) },
        @"targetWidth": @(targetWidth),
        @"targetHeight": @(targetHeight),
        @"targetDimensions": @{ @"width": @(targetWidth), @"height": @(targetHeight) },
        @"scaledWidth": @(scaledWidth),
        @"scaledHeight": @(scaledHeight),
        @"fitDimensions": @{ @"width": @(scaledWidth), @"height": @(scaledHeight) },
        @"offsetX": @(offsetX),
        @"offsetY": @(offsetY),
        @"orientation": @(orientation),
        @"unpaddedLength": @(unpadded.length),
        @"paddedLength": @(padded.length),
        @"decodedHash": decodedHash ?: @"",
        @"alphaPreserved": @YES,
        @"alphaSourceMetrics": sourceAlphaMetrics,
        @"alphaExpectedMetrics": expectedAlphaMetrics,
        @"alphaDecodedMetrics": decodedAlphaMetrics,
        @"alphaClassesPreserved": @(alphaOK),
        @"completeDecodeVerified": @YES,
    }];
    // A few importer callers use a semantically explicit spelling for the
    // staged object; retaining both costs no extra bytes because NSData is
    // immutable and shared under ARC.
    result[@"stagedBytes"] = padded;
    result[@"stagedHash"] = paddedHash;
    result[@"pngBytes"] = padded;
    result[@"unpaddedPNG"] = unpadded;
    result[@"paddedPNG"] = padded;
    result[@"paletteSize"] = @(paletteCount);
    result[@"modeFamily"] = [mode hasPrefix:@"indexed-"] ? @"indexed" : @"rgba";
    result[@"sourceSize"] = @{ @"width": @(sourceWidth), @"height": @(sourceHeight) };
    result[@"targetSize"] = @{ @"width": @(targetWidth), @"height": @(targetHeight) };
    result[@"unpaddedSHA256"] = unpaddedHash;
    result[@"paddedSHA256"] = paddedHash;
    NSMutableData *alphaTable = [NSMutableData dataWithCapacity:paletteCount];
    for (NSDictionary *entry in palette) {
        NSNumber *alpha = [entry isKindOfClass:NSDictionary.class] ? entry[@"a"] : nil;
        if (alpha != nil) {
            [alphaTable appendBytes:&(uint8_t){ alpha.unsignedCharValue } length:1u];
        }
    }
    result[@"alphaTable"] = alphaTable;
    result[@"paletteAlphaTable"] = palette ?: @[];
    return result;
}

static BOOL CNDValidateTargetDimensions(NSUInteger targetWidth,
                                        NSUInteger targetHeight,
                                        NSError **error)
{
    if (targetWidth == 0u || targetHeight == 0u) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                           @"PNG target dimensions are required.");
    }
    if (targetWidth > CNDIconThemeImageProcessorMaximumDimension ||
        targetHeight > CNDIconThemeImageProcessorMaximumDimension) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"Icon target dimensions exceed the processor limit.");
    }
    NSUInteger targetPixels = 0;
    if (!CNDMultiplySize(targetWidth, targetHeight, &targetPixels) ||
        targetPixels > CNDIconThemeImageProcessorMaximumPixels) {
        return CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                           @"Icon target pixel count exceeds the processor limit.");
    }
    return YES;
}

/// Encodes and verifies an already fitted target.  Keeping this stage separate
/// from fitting lets the multi-target API reuse one raster for descriptors
/// that differ only by appearance, variant or options.
static NSDictionary *CNDEncodeAndVerifyTarget(const CNDImage *source,
                                              uint8_t orientation,
                                              const CNDImage *target,
                                              NSData *targetRGBA,
                                              NSUInteger targetWidth,
                                              NSUInteger targetHeight,
                                              NSUInteger capacity,
                                              NSUInteger scaledWidth,
                                              NSUInteger scaledHeight,
                                              NSUInteger offsetX,
                                              NSUInteger offsetY,
                                              NSError **error)
{
    if (!source || !target || !targetRGBA) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                    @"Source and target pixels are required.");
        return nil;
    }
    NSUInteger orientedWidth = 0;
    NSUInteger orientedHeight = 0;
    CNDOrientedDimensions(source, orientation, &orientedWidth, &orientedHeight);
    NSError *lastFitError = nil;
    NSData *rgbaPNG = CNDEncodeCanonicalPNG(target, NULL, 0, NULL, &lastFitError);
    if (rgbaPNG && (capacity == 0u || rgbaPNG.length <= capacity)) {
        return CNDVerifyCandidate(
            rgbaPNG, targetRGBA, targetRGBA, @"rgba", 0u, 0u, @[], targetWidth, targetHeight,
            capacity, source->width, source->height, orientedWidth, orientedHeight,
            scaledWidth, scaledHeight, offsetX, offsetY, orientation, error);
    }
    if (rgbaPNG && rgbaPNG.length > capacity) {
        lastFitError = [NSError errorWithDomain:CNDIconThemeImageProcessorErrorDomain
                                            code:CNDIconThemeImageProcessorErrorIconDoesNotFit
                                        userInfo:@{ NSLocalizedDescriptionKey :
                                                        @"icon-fit: RGBA PNG exceeds the existing slot" }];
    }

    static const NSUInteger paletteLimits[] = { 256u, 128u, 64u };
    for (NSUInteger candidate = 0; candidate < sizeof(paletteLimits) / sizeof(paletteLimits[0]); candidate++) {
        NSUInteger paletteLimit = paletteLimits[candidate];
        CNDPaletteColor *palette = NULL;
        NSUInteger paletteCount = 0;
        uint8_t *indices = NULL;
        NSData *expectedIndexed = nil;
        NSArray *paletteArray = nil;
        if (!CNDBuildPalette(target, paletteLimit, &palette, &paletteCount,
                             &indices, &expectedIndexed, &paletteArray)) {
            continue;
        }
        NSError *encodeError = nil;
        NSData *indexedPNG = CNDEncodeCanonicalPNG(target, palette, paletteCount,
                                                   indices, &encodeError);
        free(palette);
        free(indices);
        if (!indexedPNG) {
            lastFitError = encodeError;
            continue;
        }
        if (capacity != 0u && indexedPNG.length > capacity) {
            lastFitError = [NSError errorWithDomain:CNDIconThemeImageProcessorErrorDomain
                                                code:CNDIconThemeImageProcessorErrorIconDoesNotFit
                                            userInfo:@{ NSLocalizedDescriptionKey :
                                                            @"icon-fit: indexed PNG exceeds the existing slot" }];
            continue;
        }
        NSDictionary *result = CNDVerifyCandidate(
            indexedPNG, expectedIndexed, targetRGBA,
            [NSString stringWithFormat:@"indexed-%lu", (unsigned long)paletteLimit],
            paletteLimit, paletteCount, paletteArray, targetWidth, targetHeight,
            capacity, source->width, source->height, orientedWidth, orientedHeight,
            scaledWidth, scaledHeight, offsetX, offsetY, orientation, error);
        if (result) return result;
        lastFitError = error ? *error : nil;
        if (error) *error = nil;
    }
    if (error) {
        *error = [NSError errorWithDomain:CNDIconThemeImageProcessorErrorDomain
                                     code:CNDIconThemeImageProcessorErrorIconDoesNotFit
                                 userInfo:@{ NSLocalizedDescriptionKey :
                                                 [NSString stringWithFormat:
                                                  @"icon-fit: no canonical RGBA or indexed PNG fits the %lu-byte slot",
                                                  (unsigned long)capacity],
                                             NSUnderlyingErrorKey : lastFitError ?: [NSNull null] }];
    }
    return nil;
}

static NSDictionary *CNDProcessDecodedTarget(const CNDImage *source,
                                             const CNDPNGInfo *sourceInfo,
                                             NSUInteger targetWidth,
                                             NSUInteger targetHeight,
                                             NSUInteger capacity,
                                             NSError **error)
{
    if (!CNDValidateTargetDimensions(targetWidth, targetHeight, error)) return nil;
    uint8_t orientation = sourceInfo->orientation == 0 ? 1u : sourceInfo->orientation;
    CNDImage target = { 0 };
    NSUInteger scaledWidth = 0, scaledHeight = 0, offsetX = 0, offsetY = 0;
    if (!CNDFitImage(source, orientation, targetWidth, targetHeight, &target,
                     &scaledWidth, &scaledHeight, &offsetX, &offsetY, error)) return nil;
    NSData *targetRGBA = CNDDataFromRGBA(&target);
    if (!targetRGBA) {
        CNDDestroyImage(&target);
        CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                    @"Could not snapshot the target RGBA pixels.");
        return nil;
    }
    NSDictionary *result = CNDEncodeAndVerifyTarget(source, orientation, &target,
                                                    targetRGBA, targetWidth,
                                                    targetHeight, capacity,
                                                    scaledWidth, scaledHeight,
                                                    offsetX, offsetY, error);
    CNDDestroyImage(&target);
    return result;
}

static NSDictionary *CNDProcessIconThemePNGInternal(NSData *pngData,
                                                    NSUInteger targetWidth,
                                                    NSUInteger targetHeight,
                                                    NSUInteger capacity,
                                                    NSError **error)
{
    if (error) *error = nil;
    if (!pngData || pngData.length == 0) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                    @"PNG data and target dimensions are required.");
        return nil;
    }
    if (!CNDValidateTargetDimensions(targetWidth, targetHeight, error)) return nil;
    CNDImage source = { 0 };
    CNDPNGInfo sourceInfo;
    if (!CNDDecodePNG(pngData, NO, &source, &sourceInfo, error)) return nil;
    NSDictionary *result = CNDProcessDecodedTarget(&source, &sourceInfo,
                                                   targetWidth, targetHeight,
                                                   capacity, error);
    CNDDestroyImage(&source);
    return result;
}

NSDictionary<NSString *, id> *CNDProcessIconThemePNG(NSData *pngData,
                                                      NSUInteger targetWidth,
                                                      NSUInteger targetHeight,
                                                      NSUInteger capacity,
                                                      NSError **error)
{
    return CNDProcessIconThemePNGInternal(pngData, targetWidth, targetHeight,
                                           capacity, error);
}

NSDictionary<NSString *, id> *CNDProcessIconThemePNGWithTargetSize(NSData *pngData,
                                                                    CGSize targetSize,
                                                                    NSUInteger capacity,
                                                                    NSError **error)
{
    if (targetSize.width <= 0.0 || targetSize.height <= 0.0 ||
        targetSize.width > (CGFloat)NSUIntegerMax || targetSize.height > (CGFloat)NSUIntegerMax) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                    @"Icon target size is invalid.");
        return nil;
    }
    return CNDProcessIconThemePNGInternal(pngData, (NSUInteger)targetSize.width,
                                           (NSUInteger)targetSize.height, capacity, error);
}

static NSNumber *CNDTargetNumber(NSDictionary *target, NSArray<NSString *> *keys)
{
    for (NSString *key in keys) {
        id value = target[key];
        if (![value isKindOfClass:NSNumber.class]) continue;
        NSNumber *number = value;
        double asDouble = number.doubleValue;
        if (asDouble < 0.0 || asDouble > (double)NSUIntegerMax ||
            floor(asDouble) != asDouble) continue;
        return @(number.unsignedIntegerValue);
    }
    return nil;
}

NSArray<NSDictionary<NSString *, id> *> *CNDProcessIconThemePNGForTargets(
    NSData *pngData,
    NSArray<NSDictionary<NSString *, NSNumber *> *> *targets,
    NSError **error)
{
    if (error) *error = nil;
    if (!pngData || pngData.length == 0 || ![targets isKindOfClass:NSArray.class]) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                    @"PNG data and a target array are required.");
        return nil;
    }
    // An empty target list is useful to a caller building a conditional
    // descriptor profile.  It is a no-op and does not need to decode the PNG.
    if (targets.count == 0u) return @[];

    CNDImage source = { 0 };
    CNDPNGInfo sourceInfo;
    if (!CNDDecodePNG(pngData, NO, &source, &sourceInfo, error)) return nil;

    NSMutableArray *results = [NSMutableArray arrayWithCapacity:targets.count];
    NSMutableDictionary<NSString *, NSDictionary *> *rasterCache = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSDictionary *> *resultCache = [NSMutableDictionary dictionary];
    NSUInteger sourceRGBABytes = 0u;
    NSUInteger sourcePixels = 0u;
    if (!CNDMultiplySize(source.width, source.height, &sourcePixels) ||
        !CNDMultiplySize(sourcePixels, 4u, &sourceRGBABytes)) {
        CNDDestroyImage(&source);
        CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                    @"Source RGBA storage arithmetic overflowed.");
        return nil;
    }
    NSUInteger cachedRasterBytes = sourceRGBABytes;
    for (id candidate in targets) {
        if (![candidate isKindOfClass:NSDictionary.class]) {
            CNDDestroyImage(&source);
            CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                        @"Each PNG target must be a dictionary.");
            return nil;
        }
        NSDictionary *targetSpec = candidate;
        NSNumber *widthNumber = CNDTargetNumber(targetSpec, @[ @"width", @"targetWidth" ]);
        NSNumber *heightNumber = CNDTargetNumber(targetSpec, @[ @"height", @"targetHeight" ]);
        NSNumber *capacityNumber = CNDTargetNumber(targetSpec, @[ @"capacity" ]);
        if (widthNumber == nil || heightNumber == nil ||
            (targetSpec[@"capacity"] != nil && capacityNumber == nil)) {
            CNDDestroyImage(&source);
            CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                        @"Each PNG target requires integral width and height values.");
            return nil;
        }
        NSUInteger width = widthNumber.unsignedIntegerValue;
        NSUInteger height = heightNumber.unsignedIntegerValue;
        NSUInteger capacity = capacityNumber != nil
            ? capacityNumber.unsignedIntegerValue : 0u;
        if (!CNDValidateTargetDimensions(width, height, error)) {
            CNDDestroyImage(&source);
            return nil;
        }

        NSString *rasterKey = [NSString stringWithFormat:@"%lux%lu", (unsigned long)width, (unsigned long)height];
        NSDictionary *raster = rasterCache[rasterKey];
        if (!raster) {
            uint8_t orientation = sourceInfo.orientation == 0 ? 1u : sourceInfo.orientation;
            CNDImage target = { 0 };
            NSUInteger scaledWidth = 0, scaledHeight = 0, offsetX = 0, offsetY = 0;
            if (!CNDFitImage(&source, orientation, width, height, &target,
                             &scaledWidth, &scaledHeight, &offsetX, &offsetY, error)) {
                CNDDestroyImage(&source);
                return nil;
            }
            NSData *targetRGBA = CNDDataFromRGBA(&target);
            if (!targetRGBA) {
                CNDDestroyImage(&target);
                CNDDestroyImage(&source);
                CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                            @"Could not snapshot the target RGBA pixels.");
                return nil;
            }
            if (targetRGBA.length > kCNDMaximumDecodedBytes -
                    MIN(cachedRasterBytes, kCNDMaximumDecodedBytes)) {
                CNDDestroyImage(&target);
                CNDDestroyImage(&source);
                CNDSetError(error, CNDIconThemeImageProcessorErrorResourceLimit,
                            @"Decoded source and multi-target raster storage exceeds the processor limit.");
                return nil;
            }
            cachedRasterBytes += targetRGBA.length;
            raster = @{
                @"rgba": targetRGBA,
                @"scaledWidth": @(scaledWidth),
                @"scaledHeight": @(scaledHeight),
                @"offsetX": @(offsetX),
                @"offsetY": @(offsetY),
            };
            rasterCache[rasterKey] = raster;
            CNDDestroyImage(&target);
        }

        NSString *resultKey = [NSString stringWithFormat:@"%@/%lu", rasterKey, (unsigned long)capacity];
        NSDictionary *cachedResult = resultCache[resultKey];
        if (cachedResult) {
            [results addObject:cachedResult];
            continue;
        }
        NSData *targetRGBA = raster[@"rgba"];
        CNDImage targetView = {
            width, height, (uint8_t *)targetRGBA.bytes
        };
        NSError *targetError = nil;
        NSDictionary *result = CNDEncodeAndVerifyTarget(
            &source, sourceInfo.orientation == 0 ? 1u : sourceInfo.orientation,
            &targetView, targetRGBA, width, height, capacity,
            [raster[@"scaledWidth"] unsignedIntegerValue],
            [raster[@"scaledHeight"] unsignedIntegerValue],
            [raster[@"offsetX"] unsignedIntegerValue],
            [raster[@"offsetY"] unsignedIntegerValue], &targetError);
        if (!result) {
            CNDDestroyImage(&source);
            if (error) *error = targetError;
            return nil;
        }
        resultCache[resultKey] = result;
        [results addObject:result];
    }
    CNDDestroyImage(&source);
    return [results copy];
}

NSArray<NSDictionary<NSString *, id> *> *CNDProcessIconThemePNGWithTargetSizes(
    NSData *pngData,
    NSArray<NSValue *> *targetSizes,
    NSArray<NSNumber *> *capacities,
    NSError **error)
{
    if (error) *error = nil;
    if (![targetSizes isKindOfClass:NSArray.class] ||
        (capacities != nil && (![capacities isKindOfClass:NSArray.class] ||
                                capacities.count != targetSizes.count))) {
        CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                    @"Target sizes and capacities must be arrays of equal length.");
        return nil;
    }
    NSMutableArray *targets = [NSMutableArray arrayWithCapacity:targetSizes.count];
    for (NSUInteger index = 0u; index < targetSizes.count; index++) {
        NSValue *value = targetSizes[index];
        CGSize size = CGSizeZero;
        if (![value isKindOfClass:NSValue.class] ||
            strcmp(value.objCType, @encode(CGSize)) != 0) {
            CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                        @"Each target size must be an NSValue containing CGSize.");
            return nil;
        }
        [value getValue:&size];
        if (!isfinite(size.width) || !isfinite(size.height) ||
            size.width <= 0.0 || size.height <= 0.0 ||
            floor(size.width) != size.width || floor(size.height) != size.height ||
            size.width > (CGFloat)NSUIntegerMax || size.height > (CGFloat)NSUIntegerMax) {
            CNDSetError(error, CNDIconThemeImageProcessorErrorInvalidArgument,
                        @"Target sizes must contain finite positive integral dimensions.");
            return nil;
        }
        NSMutableDictionary *target = [@{ @"width": @((NSUInteger)size.width),
                                           @"height": @((NSUInteger)size.height) } mutableCopy];
        if (capacities) target[@"capacity"] = capacities[index];
        [targets addObject:target];
    }
    return CNDProcessIconThemePNGForTargets(pngData, targets, error);
}

@implementation CNDIconThemeImageProcessor

+ (NSDictionary<NSString *,id> *)processPNGData:(NSData *)pngData
                                     targetWidth:(NSUInteger)targetWidth
                                    targetHeight:(NSUInteger)targetHeight
                                       capacity:(NSUInteger)capacity
                                           error:(NSError **)error
{
    return CNDProcessIconThemePNG(pngData, targetWidth, targetHeight, capacity, error);
}

+ (NSDictionary<NSString *,id> *)processPNGData:(NSData *)pngData
                                       targetSize:(CGSize)targetSize
                                        capacity:(NSUInteger)capacity
                                           error:(NSError **)error
{
    return CNDProcessIconThemePNGWithTargetSize(pngData, targetSize, capacity, error);
}

+ (NSDictionary<NSString *,id> *)processImageData:(NSData *)imageData
                                        targetWidth:(NSUInteger)targetWidth
                                       targetHeight:(NSUInteger)targetHeight
                                          capacity:(NSUInteger)capacity
                                              error:(NSError **)error
{
    return CNDProcessIconThemePNG(imageData, targetWidth, targetHeight, capacity, error);
}

+ (NSArray<NSDictionary<NSString *,id> *> *)processPNGData:(NSData *)pngData
                                                    targets:(NSArray<NSDictionary<NSString *,NSNumber *> *> *)targets
                                                       error:(NSError **)error
{
    return CNDProcessIconThemePNGForTargets(pngData, targets, error);
}

+ (NSArray<NSDictionary<NSString *,id> *> *)processPNGData:(NSData *)pngData
                                                targetSizes:(NSArray<NSValue *> *)targetSizes
                                                  capacities:(NSArray<NSNumber *> *)capacities
                                                       error:(NSError **)error
{
    return CNDProcessIconThemePNGWithTargetSizes(pngData, targetSizes, capacities, error);
}

@end
