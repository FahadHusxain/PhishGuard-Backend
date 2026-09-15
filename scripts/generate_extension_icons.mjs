import {deflateSync} from "node:zlib";
import {mkdirSync, writeFileSync} from "node:fs";
import {dirname, join} from "node:path";
import {fileURLToPath} from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const outputDirectory = join(root, "browser-extension", "icons");

function crc32(buffer) {
    let crc = 0xffffffff;
    for (const byte of buffer) {
        crc ^= byte;
        for (let bit = 0; bit < 8; bit += 1) {
            crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
        }
    }
    return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
    const name = Buffer.from(type, "ascii");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    const checksum = Buffer.alloc(4);
    checksum.writeUInt32BE(crc32(Buffer.concat([name, data])));
    return Buffer.concat([length, name, data, checksum]);
}

function insidePolygon(x, y, points) {
    let inside = false;
    for (let current = 0, previous = points.length - 1; current < points.length; previous = current, current += 1) {
        const [x1, y1] = points[current];
        const [x2, y2] = points[previous];
        if ((y1 > y) !== (y2 > y) && x < ((x2 - x1) * (y - y1)) / (y2 - y1) + x1) {
            inside = !inside;
        }
    }
    return inside;
}

function distanceToSegment(x, y, x1, y1, x2, y2) {
    const dx = x2 - x1;
    const dy = y2 - y1;
    const projection = Math.max(0, Math.min(1, ((x - x1) * dx + (y - y1) * dy) / (dx * dx + dy * dy)));
    return Math.hypot(x - (x1 + projection * dx), y - (y1 + projection * dy));
}

function render(size) {
    const rows = [];
    const shield = [[.5, .1], [.82, .22], [.76, .7], [.5, .9], [.24, .7], [.18, .22]];
    for (let y = 0; y < size; y += 1) {
        const row = Buffer.alloc(1 + size * 4);
        for (let x = 0; x < size; x += 1) {
            const px = (x + .5) / size;
            const py = (y + .5) / size;
            let color = [8, 42, 49, 255];
            if (insidePolygon(px, py, shield)) color = [66, 211, 255, 255];
            if (distanceToSegment(px, py, .34, .49, .46, .61) < .035 || distanceToSegment(px, py, .46, .61, .69, .35) < .035) {
                color = [74, 222, 128, 255];
            }
            row.set(color, 1 + x * 4);
        }
        rows.push(row);
    }
    const header = Buffer.alloc(13);
    header.writeUInt32BE(size, 0);
    header.writeUInt32BE(size, 4);
    header.set([8, 6, 0, 0, 0], 8);
    return Buffer.concat([
        Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
        chunk("IHDR", header),
        chunk("IDAT", deflateSync(Buffer.concat(rows), {level: 9})),
        chunk("IEND", Buffer.alloc(0)),
    ]);
}

mkdirSync(outputDirectory, {recursive: true});
for (const size of [16, 32, 48, 128]) {
    writeFileSync(join(outputDirectory, `icon-${size}.png`), render(size));
}
console.log("Generated PhishGuard extension icons: 16, 32, 48, 128 px");
