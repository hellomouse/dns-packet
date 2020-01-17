import types = require('./types')
import rcodes = require('./rcodes')
import opcodes = require('./opcodes')
import classes = require('./classes')
import optioncodes = require('./optioncodes')
import ip = require('ip')

const QUERY_FLAG = 0
const RESPONSE_FLAG = 1 << 15
const FLUSH_MASK = 1 << 15
const NOT_FLUSH_MASK = ~FLUSH_MASK
const QU_MASK = 1 << 15
const NOT_QU_MASK = ~QU_MASK

interface encode {
  (str: string, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface decode {
  (buf: Buffer, offset?: number): string
  bytes: number
}
const name = {
  encode: function (str: string, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(name.encodingLength(str))
    if (!offset) offset = 0
    const oldOffset = offset

    // strip leading and trailing .
    const n = str.replace(/^\.|\.$/gm, '')
    if (n.length) {
      const list = n.split('.')

      for (let i = 0; i < list.length; i++) {
        const len = buf.write(list[i], offset + 1)
        buf[offset] = len
        offset += len + 1
      }
    }

    buf[offset++] = 0

    name.encode.bytes = offset - oldOffset
    return buf
  } as encode,

  decode: function (buf: Buffer, offset?: number): string {
    if (!offset) offset = 0

    const list = []
    const oldOffset = offset
    let len = buf[offset++]

    if (len === 0) {
      name.decode.bytes = 1
      return '.'
    }
    if (len >= 0xc0) {
      const res = name.decode(buf, buf.readUInt16BE(offset - 1) - 0xc000)
      name.decode.bytes = 2
      return res
    }

    while (len) {
      if (len >= 0xc0) {
        list.push(name.decode(buf, buf.readUInt16BE(offset - 1) - 0xc000))
        offset++
        break
      }

      list.push(buf.toString('utf-8', offset, offset + len))
      offset += len
      len = buf[offset++]
    }

    name.decode.bytes = offset - oldOffset
    return list.join('.')
  } as decode,

  encodingLength: function (n: string) {
    if (n === '.') return 1
    return Buffer.byteLength(n) + 2
  }
}
name.encode.bytes = 0
name.decode.bytes = 0

const string = {
  encode: function (s: string, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(string.encodingLength(s))
    if (!offset) offset = 0

    const len = buf.write(s, offset + 1)
    buf[offset] = len
    string.encode.bytes = len + 1
    return buf
  } as encode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    const len = buf[offset]
    const s = buf.toString('utf-8', offset + 1, offset + 1 + len)
    string.decode.bytes = len + 1
    return s
  } as decode,

  encodingLength: function (s: string) {
    return Buffer.byteLength(s) + 1
  }
}
string.encode.bytes = 0
string.decode.bytes = 0

interface HeaderData {
  id: number;
  type: 'response' | 'query';
  flags: number;
  flag_qr: boolean;
  opcode: string;
  flag_aa: boolean;
  flag_tc: boolean;
  flag_rd: boolean;
  flag_ra: boolean;
  flag_z: boolean;
  flag_ad: boolean;
  flag_cd: boolean;
  rcode: string;
  questions: Question[];
  answers: answer[]
  authorities: any[]
  additionals: any[]
}
interface HeaderEncode {
  (h: HeaderData, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface HeaderDecode {
  (buf: Buffer, offset?: number): HeaderData
  bytes: number
}

const header = {
  encode: function (h: HeaderData, buf?: Buffer, offset?: number) {
    const bufs: Buffer = buf || Buffer.alloc(header.encodingLength())
    if (!offset) offset = 0

    const flags = (h.flags || 0) & 32767
    const type = h.type === 'response' ? RESPONSE_FLAG : QUERY_FLAG

    bufs.writeUInt16BE(h.id || 0, offset)
    bufs.writeUInt16BE(flags | type, offset + 2)
    bufs.writeUInt16BE(h.questions.length, offset + 4)
    bufs.writeUInt16BE(h.answers.length, offset + 6)
    bufs.writeUInt16BE(h.authorities.length, offset + 8)
    bufs.writeUInt16BE(h.additionals.length, offset + 10)

    return bufs
  } as HeaderEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    if (buf.length < 12) throw new Error('Header must be 12 bytes')
    const flags = buf.readUInt16BE(offset + 2)

    return {
      id: buf.readUInt16BE(offset),
      type: flags & RESPONSE_FLAG ? 'response' : 'query',
      flags: flags & 32767,
      flag_qr: ((flags >> 15) & 0x1) === 1,
      opcode: opcodes.toString((flags >> 11) & 0xf),
      flag_aa: ((flags >> 10) & 0x1) === 1,
      flag_tc: ((flags >> 9) & 0x1) === 1,
      flag_rd: ((flags >> 8) & 0x1) === 1,
      flag_ra: ((flags >> 7) & 0x1) === 1,
      flag_z: ((flags >> 6) & 0x1) === 1,
      flag_ad: ((flags >> 5) & 0x1) === 1,
      flag_cd: ((flags >> 4) & 0x1) === 1,
      rcode: rcodes.toString(flags & 0xf),
      questions: new Array(buf.readUInt16BE(offset + 4)),
      answers: new Array(buf.readUInt16BE(offset + 6)),
      authorities: new Array(buf.readUInt16BE(offset + 8)),
      additionals: new Array(buf.readUInt16BE(offset + 10))
    }
  } as HeaderDecode,

  encodingLength: function () {
    return 12
  }
}
header.encode.bytes = 12
header.decode.bytes = 12

interface runknownEncode {
  (data: Buffer, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface runknownDecode {
  (buf: Buffer, offset?: number): Buffer
  bytes: number
}

const runknown = {
  encode: function (data: Buffer, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(runknown.encodingLength(data))
    if (!offset) offset = 0

    buf.writeUInt16BE(data.length, offset)
    data.copy(buf, offset + 2)

    runknown.encode.bytes = data.length + 2
    return buf
  } as runknownEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    const len = buf.readUInt16BE(offset)
    const data = buf.slice(offset + 2, offset + 2 + len)
    runknown.decode.bytes = len + 2
    return data
  } as runknownDecode,

  encodingLength: function (data: Buffer) {
    return data.length + 2
  }
}
runknown.encode.bytes = 0
runknown.decode.bytes = 0

interface rnsEncode {
  (data: string, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rnsDecode {
  (buf: Buffer, offset?: number): string
  bytes: number
}
const rns = {
  encode: function (data: string, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rns.encodingLength(data))
    if (!offset) offset = 0

    name.encode(data, buf, offset + 2)
    buf.writeUInt16BE(name.encode.bytes, offset)
    rns.encode.bytes = name.encode.bytes + 2
    return buf
  } as rnsEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    const len = buf.readUInt16BE(offset)
    const dd = name.decode(buf, offset + 2)

    rns.decode.bytes = len + 2
    return dd
  } as rnsDecode,

  encodingLength: function (data: string) {
    return name.encodingLength(data) + 2
  }
}
rns.encode.bytes = 0
rns.decode.bytes = 0

interface SOAEncode {
  (data: SOAData, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface SOADecode {
  (buf: Buffer, offset?: number): SOAData
  bytes: number
}
interface SOAData {
  mname: string;
  rname: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number
}
const rsoa = {

  encode: function (data: SOAData, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rsoa.encodingLength(data))
    if (!offset) offset = 0

    const oldOffset = offset
    offset += 2
    name.encode(data.mname, buf, offset)
    offset += name.encode.bytes
    name.encode(data.rname, buf, offset)
    offset += name.encode.bytes
    buf.writeUInt32BE(data.serial || 0, offset)
    offset += 4
    buf.writeUInt32BE(data.refresh || 0, offset)
    offset += 4
    buf.writeUInt32BE(data.retry || 0, offset)
    offset += 4
    buf.writeUInt32BE(data.expire || 0, offset)
    offset += 4
    buf.writeUInt32BE(data.minimum || 0, offset)
    offset += 4

    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset)
    rsoa.encode.bytes = offset - oldOffset
    return buf
  } as SOAEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    const oldOffset = offset

    const data: any = {}
    offset += 2
    data.mname = name.decode(buf, offset)
    offset += name.decode.bytes
    data.rname = name.decode(buf, offset)
    offset += name.decode.bytes
    data.serial = buf.readUInt32BE(offset)
    offset += 4
    data.refresh = buf.readUInt32BE(offset)
    offset += 4
    data.retry = buf.readUInt32BE(offset)
    offset += 4
    data.expire = buf.readUInt32BE(offset)
    offset += 4
    data.minimum = buf.readUInt32BE(offset)
    offset += 4

    rsoa.decode.bytes = offset - oldOffset
    return data
  } as SOADecode,

  encodingLength: function (data: SOAData) {
    return 22 + name.encodingLength(data.mname) + name.encodingLength(data.rname)
  }
}

rsoa.encode.bytes = 0
rsoa.decode.bytes = 0

interface rtxtEncode {
  (data: (string | Buffer)[] | string | Buffer, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rtxtDecode {
  (buf: Buffer, offset?: number): Buffer[]
  bytes: number
}

const rtxt = {
  encode: function (data: (string | Buffer)[] | string | Buffer, buf?: Buffer, offset?: number) {
    let newdata: any[] = []
    if (!Array.isArray(data)) newdata = [data]
    for (let i = 0; i < data.length; i++) {
      if (typeof data[i] === 'string') {
        newdata[i] = Buffer.from(data[i] as string)
      }
      if (!Buffer.isBuffer(data[i])) {
        throw new Error('Must be a Buffer')
      } else {
        newdata[i] = data[i] as Buffer
      }
    }

    const bufs: Buffer = buf || Buffer.allocUnsafe(rtxt.encodingLength(newdata))
    if (!offset) offset = 0

    const oldOffset = offset
    offset += 2

    newdata.forEach(function (d) {
      bufs[offset!++] = d.length
      d.copy(buf!, offset, 0, d.length)
      offset! += d.length
    })

    bufs.writeUInt16BE(offset - oldOffset - 2, oldOffset)
    rtxt.encode.bytes = offset - oldOffset
    return bufs
  } as rtxtEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    const oldOffset = offset
    let remaining = buf.readUInt16BE(offset)
    offset += 2

    const data = []
    while (remaining > 0) {
      const len = buf[offset++]
      --remaining
      if (remaining < len) {
        throw new Error('Buffer overflow')
      }
      data.push(buf.slice(offset, offset + len))
      offset += len
      remaining -= len
    }

    rtxt.decode.bytes = offset - oldOffset
    return data
  } as rtxtDecode,

  encodingLength: function (data: (string| Buffer)[] | string | Buffer) {
    if (!Array.isArray(data)) data = [data]
    let length = 2
    data.forEach(function (buf) {
      if (typeof buf === 'string') {
        length += Buffer.byteLength(buf) + 1
      } else {
        length += buf.length + 1
      }
    })
    return length
  }
}
rtxt.encode.bytes = 0
rtxt.decode.bytes = 0

interface rnullEncode {
  (data: string | Buffer, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rnullDecode {
  (buf: Buffer, offset?: number): Buffer
  bytes: number
}
const rnull = {
  encode: function (data: string | Buffer, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rnull.encodingLength(data))
    if (!offset) offset = 0

    if (typeof data === 'string') data = Buffer.from(data)
    if (!data) data = Buffer.allocUnsafe(0)

    const oldOffset = offset
    offset += 2

    const len = data.length
    data.copy(buf, offset, 0, len)
    offset += len

    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset)
    rnull.encode.bytes = offset - oldOffset
    return buf
  } as rnullEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    const oldOffset = offset
    const len = buf.readUInt16BE(offset)

    offset += 2

    const data = buf.slice(offset, offset + len)
    offset += len

    rnull.decode.bytes = offset - oldOffset
    return data
  } as rnullDecode,

  encodingLength: function (data: string | Buffer) {
    if (!data) return 2
    return (Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data)) + 2
  }
}
rnull.encode.bytes = 0
rnull.decode.bytes = 0

interface rhInfo {
  os: string
  cpu: string
}
interface rhInfoEncode {
  (data: rhInfo, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rhInfoDecode {
  (buf: Buffer, offset?: number): rhInfo
  bytes: number
}
const rhinfo = {
  encode: function (data: rhInfo, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rhinfo.encodingLength(data))
    if (!offset) offset = 0

    const oldOffset = offset
    offset += 2
    string.encode(data.cpu, buf, offset)
    offset += string.encode.bytes
    string.encode(data.os, buf, offset)
    offset += string.encode.bytes
    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset)
    rhinfo.encode.bytes = offset - oldOffset
    return buf
  } as rhInfoEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    const oldOffset = offset

    const data: any = {}
    offset += 2
    data.cpu = string.decode(buf, offset)
    offset += string.decode.bytes
    data.os = string.decode(buf, offset)
    offset += string.decode.bytes
    rhinfo.decode.bytes = offset - oldOffset
    return data as rhInfo
  } as rhInfoDecode,

  encodingLength: function (data: rhInfo) {
    return string.encodingLength(data.cpu) + string.encodingLength(data.os) + 2
  }
}
rhinfo.encode.bytes = 0
rhinfo.decode.bytes = 0

interface rPTREncode {
  (data: string, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rPTRDecode {
  (buf: Buffer, offset?: number): string
  bytes: number
}
const rptr = {
  encode: function (data: string, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rptr.encodingLength(data))
    if (!offset) offset = 0

    name.encode(data, buf, offset + 2)
    buf.writeUInt16BE(name.encode.bytes, offset)
    rptr.encode.bytes = name.encode.bytes + 2
    return buf
  } as rPTREncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    const data = name.decode(buf, offset + 2)
    rptr.decode.bytes = name.decode.bytes + 2
    return data
  } as rPTRDecode,

  encodingLength: function (data: string) {
    return name.encodingLength(data) + 2
  }
}
rptr.encode.bytes = 0
rptr.decode.bytes = 0

const rcname = rptr
const rdname = rptr

interface SRVData {
  priority: number;
  weight: number;
  port: number;
  target: string;
}
interface rSRVEncode {
  (data: SRVData, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rSRVDecode {
  (buf: Buffer, offset?: number): SRVData
  bytes: number
}
const rsrv = {
  encode: function (data: SRVData, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rsrv.encodingLength(data))
    if (!offset) offset = 0

    buf.writeUInt16BE(data.priority || 0, offset + 2)
    buf.writeUInt16BE(data.weight || 0, offset + 4)
    buf.writeUInt16BE(data.port || 0, offset + 6)
    name.encode(data.target, buf, offset + 8)

    const len = name.encode.bytes + 6
    buf.writeUInt16BE(len, offset)

    rsrv.encode.bytes = len + 2
    return buf
  } as rSRVEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    const len = buf.readUInt16BE(offset)

    const data = {
      priority: buf.readUInt16BE(offset + 2),
      weight: buf.readUInt16BE(offset + 4),
      port: buf.readUInt16BE(offset + 6),
      target: name.decode(buf, offset + 8)
    }

    rsrv.decode.bytes = len + 2
    return data
  } as rSRVDecode,

  encodingLength: function (data: SRVData) {
    return 8 + name.encodingLength(data.target)
  }
}
rsrv.encode.bytes = 0
rsrv.decode.bytes = 0

interface CAA {
  issuerCritical: boolean;
  flags: number;
  tag: string;
  value: string
}
interface rCAAEncode {
  (data: CAA, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rCAADecode {
  (buf: Buffer, offset?: number): CAA
  bytes: number
}
const rcaa = {
  ISSUER_CRITICAL: 1 << 7,

  encode: function (data: CAA, buf?: Buffer, offset?: number) {
    const len = rcaa.encodingLength(data)

    if (!buf) buf = Buffer.allocUnsafe(rcaa.encodingLength(data))
    if (!offset) offset = 0

    if (data.issuerCritical) {
      data.flags = rcaa.ISSUER_CRITICAL
    }

    buf.writeUInt16BE(len - 2, offset)
    offset += 2
    buf.writeUInt8(data.flags || 0, offset)
    offset += 1
    string.encode(data.tag, buf, offset)
    offset += string.encode.bytes
    buf.write(data.value, offset)
    offset += Buffer.byteLength(data.value)

    rcaa.encode.bytes = len
    return buf
  } as rCAAEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    const len = buf.readUInt16BE(offset)
    offset += 2

    const oldOffset = offset
    let data: any
    data!.flags = buf.readUInt8(offset)
    offset += 1
    data!.tag = string.decode(buf, offset)
    offset += string.decode.bytes
    data!.value = buf.toString('utf-8', offset, oldOffset + len)

    data!.issuerCritical = !!(data!.flags & rcaa.ISSUER_CRITICAL)

    rcaa.decode.bytes = len + 2

    return data as CAA
  } as rCAADecode,

  encodingLength: function (data: CAA) {
    return string.encodingLength(data.tag) + string.encodingLength(data.value) + 2
  }
}
rcaa.encode.bytes = 0
rcaa.decode.bytes = 0

interface rMXData {
  preference: number;
  exchange: string;
}
interface rMXEncode {
  (data: rMXData, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rMXDecode {
  (buf: Buffer, offset?: number): rMXData
  bytes: number
}
const rmx = {
  encode: function (data: rMXData, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rmx.encodingLength(data))
    if (!offset) offset = 0

    const oldOffset = offset
    offset += 2
    buf.writeUInt16BE(data.preference || 0, offset)
    offset += 2
    name.encode(data.exchange, buf, offset)
    offset += name.encode.bytes

    buf.writeUInt16BE(offset - oldOffset - 2, oldOffset)
    rmx.encode.bytes = offset - oldOffset
    return buf
  } as rMXEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    const oldOffset = offset

    const data: any = {}
    offset += 2
    data.preference = buf.readUInt16BE(offset)
    offset += 2
    data.exchange = name.decode(buf, offset)
    offset += name.decode.bytes

    rmx.decode.bytes = offset - oldOffset
    return data as rMXData
  } as rMXDecode,

  encodingLength: function (data: rMXData) {
    return 4 + name.encodingLength(data.exchange)
  }
}
rmx.encode.bytes = 0
rmx.decode.bytes = 0

interface rAEncode {
  (host: string, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rADecode {
  (buf: Buffer, offset?: number): string
  bytes: number
}
const ra = {
  encode: function (host: string, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(ra.encodingLength())
    if (!offset) offset = 0

    buf.writeUInt16BE(4, offset)
    offset += 2
    ip.toBuffer(host, buf, offset)
    ra.encode.bytes = 6
    return buf
  } as rAEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    offset += 2
    const host = ip.toString(buf, offset, 4)
    ra.decode.bytes = 6
    return host
  } as rADecode,

  encodingLength: function () {
    return 6
  }
}
ra.encode.bytes = 0
ra.decode.bytes = 0

interface rAAAAEncode {
  (host: string, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rAAAADecode {
  (buf: Buffer, offset?: number): string
  bytes: number
}
const raaaa = {
  encode: function (host: string, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(raaaa.encodingLength())
    if (!offset) offset = 0

    buf.writeUInt16BE(16, offset)
    offset += 2
    ip.toBuffer(host, buf, offset)
    raaaa.encode.bytes = 18
    return buf
  } as rAAAAEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    offset += 2
    const host = ip.toString(buf, offset, 16)
    raaaa.decode.bytes = 18
    return host
  } as rAAAADecode,

  encodingLength: function () {
    return 18
  }
}
raaaa.encode.bytes = 0
raaaa.decode.bytes = 0

interface rOptionData {
  code: number
  type: string | null
  data: Buffer
  family: number
  sourcePrefixLength: number
  scopePrefixLength: number
  ip: string
  timeout: number
  tags: number[]
  length: number
}
interface rOptionEncode {
  (option: rOptionData, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rOptionDecode {
  (buf: Buffer, offset?: number): rOptionData
  bytes: number
}
const roption = {
  encode: function (option: rOptionData, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(roption.encodingLength(option))
    if (!offset) offset = 0
    const oldOffset = offset

    const code = optioncodes.toCode(option.code)
    buf.writeUInt16BE(code, offset)
    offset += 2
    if (option.data) {
      buf.writeUInt16BE(option.data.length, offset)
      offset += 2
      option.data.copy(buf, offset)
      offset += option.data.length
    } else {
      switch (code) {
        // case 3: NSID.  No encode makes sense.
        // case 5,6,7: Not implementable
        case 8: // ECS
          // note: do IP math before calling
          const spl = option.sourcePrefixLength || 0
          const fam = option.family || (ip.isV4Format(option.ip) ? 1 : 2)
          const ipBuf = ip.toBuffer(option.ip)
          const ipLen = Math.ceil(spl / 8)
          buf.writeUInt16BE(ipLen + 4, offset)
          offset += 2
          buf.writeUInt16BE(fam, offset)
          offset += 2
          buf.writeUInt8(spl, offset++)
          buf.writeUInt8(option.scopePrefixLength || 0, offset++)

          ipBuf.copy(buf, offset, 0, ipLen)
          offset += ipLen
          break
        // case 9: EXPIRE (experimental)
        // case 10: COOKIE.  No encode makes sense.
        case 11: // KEEP-ALIVE
          if (option.timeout) {
            buf.writeUInt16BE(2, offset)
            offset += 2
            buf.writeUInt16BE(option.timeout, offset)
            offset += 2
          } else {
            buf.writeUInt16BE(0, offset)
            offset += 2
          }
          break
        case 12: // PADDING
          const len = option.length || 0
          buf.writeUInt16BE(len, offset)
          offset += 2
          buf.fill(0, offset, offset + len)
          offset += len
          break
        // case 13:  CHAIN.  Experimental.
        case 14: // KEY-TAG
          const tagsLen = option.tags.length * 2
          buf.writeUInt16BE(tagsLen, offset)
          offset += 2
          for (const tag of option.tags) {
            buf.writeUInt16BE(tag, offset)
            offset += 2
          }
          break
        default:
          throw new Error(`Unknown roption code: ${option.code}`)
      }
    }

    roption.encode.bytes = offset - oldOffset
    return buf
  } as rOptionEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    const option: any = {}
    option.code = buf.readUInt16BE(offset)
    option.type = optioncodes.toString(option.code)
    offset += 2
    const len = buf.readUInt16BE(offset)
    offset += 2
    option.data = buf.slice(offset, offset + len)
    switch (option.code) {
      // case 3: NSID.  No decode makes sense.
      case 8: // ECS
        option.family = buf.readUInt16BE(offset)
        offset += 2
        option.sourcePrefixLength = buf.readUInt8(offset++)
        option.scopePrefixLength = buf.readUInt8(offset++)
        const padded = Buffer.alloc((option.family === 1) ? 4 : 16)
        buf.copy(padded, 0, offset, offset + len - 4)
        option.ip = ip.toString(padded)
        break
      // case 12: Padding.  No decode makes sense.
      case 11: // KEEP-ALIVE
        if (len > 0) {
          option.timeout = buf.readUInt16BE(offset)
          offset += 2
        }
        break
      case 14:
        option.tags = []
        for (let i = 0; i < len; i += 2) {
          option.tags.push(buf.readUInt16BE(offset))
          offset += 2
        }
      // don't worry about default.  caller will use data if desired
    }

    roption.decode.bytes = len + 4
    return option as rOptionData
  } as rOptionDecode,

  encodingLength: function (option: rOptionData) {
    if (option.data) {
      return option.data.length + 4
    }
    const code = optioncodes.toCode(option.code)
    switch (code) {
      case 8: // ECS
        const spl = option.sourcePrefixLength || 0
        return Math.ceil(spl / 8) + 8
      case 11: // KEEP-ALIVE
        return (typeof option.timeout === 'number') ? 6 : 4
      case 12: // PADDING
        return option.length + 4
      case 14: // KEY-TAG
        return 4 + (option.tags.length * 2)
    }
    throw new Error(`Unknown roption code: ${option.code}`)
  }
}
roption.encode.bytes = 0
roption.decode.bytes = 0

interface rOptEncode {
  (options: rOptionData[], buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rOptDecode {
  (buf: Buffer, offset?: number): rOptionData[]
  bytes: number
}
const ropt = {
  encode: function (options: rOptionData[], buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(ropt.encodingLength(options))
    if (!offset) offset = 0
    const oldOffset = offset

    const rdlen = encodingLengthList(options, roption)
    buf.writeUInt16BE(rdlen, offset)
    offset = encodeList(options, roption, buf, offset + 2)

    ropt.encode.bytes = offset! - oldOffset
    return buf
  } as rOptEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    const oldOffset = offset

    const options: rOptionData[] = []
    let rdlen = buf.readUInt16BE(offset)
    offset += 2
    let o = 0
    while (rdlen > 0) {
      options[o++] = roption.decode(buf, offset)
      offset += roption.decode.bytes
      rdlen -= roption.decode.bytes
    }
    ropt.decode.bytes = offset - oldOffset
    return options
  } as rOptDecode,

  encodingLength: function (options: rOptionData[]) {
    return 2 + encodingLengthList(options || [], roption)
  }
}
ropt.encode.bytes = 0
ropt.decode.bytes = 0

interface rDNSKey {
  key: Buffer;
  flags: number;
  algorithm: number
}
interface rDNSKeyEncode {
  (key: rDNSKey, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rDNSKeyDecode {
  (buf: Buffer, offset?: number): rDNSKey
  bytes: number
}
const rdnskey = {
  PROTOCOL_DNSSEC: 3,
  ZONE_KEY: 0x80,
  SECURE_ENTRYPOINT: 0x8000,

  encode: function (key: rDNSKey, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rdnskey.encodingLength(key))
    if (!offset) offset = 0
    const oldOffset = offset

    const keydata = key.key
    if (!Buffer.isBuffer(keydata)) {
      throw new Error('Key must be a Buffer')
    }

    offset += 2 // Leave space for length
    buf.writeUInt16BE(key.flags, offset)
    offset += 2
    buf.writeUInt8(rdnskey.PROTOCOL_DNSSEC, offset)
    offset += 1
    buf.writeUInt8(key.algorithm, offset)
    offset += 1
    keydata.copy(buf, offset, 0, keydata.length)
    offset += keydata.length

    rdnskey.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rdnskey.encode.bytes - 2, oldOffset)
    return buf
  } as rDNSKeyEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    const oldOffset = offset

    const key: any = {}
    const length = buf.readUInt16BE(offset)
    offset += 2
    key.flags = buf.readUInt16BE(offset)
    offset += 2
    if (buf.readUInt8(offset) !== rdnskey.PROTOCOL_DNSSEC) {
      throw new Error('Protocol must be 3')
    }
    offset += 1
    key.algorithm = buf.readUInt8(offset)
    offset += 1
    key.key = buf.slice(offset, oldOffset + length + 2)
    offset += key.key.length
    rdnskey.decode.bytes = offset - oldOffset
    return key as rDNSKey
  } as rDNSKeyDecode,

  encodingLength: function (key: rDNSKey) {
    return 6 + Buffer.byteLength(key.key)
  }
}

rdnskey.encode.bytes = 0
rdnskey.decode.bytes = 0

interface rRRSIG {
  signature: Buffer;
  typeCovered: string;
  algorithm: number;
  labels: number;
  originalTTL: number;
  expiration: number;
  inception: number;
  keyTag: number;
  signersName: string;
}
interface rRRSIGEncode {
  (sig: rRRSIG, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rRRSIGDecode {
  (buf: Buffer, offset?: number): rRRSIG
  bytes: number
}

const rrrsig = {
  encode: function (sig: rRRSIG, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rrrsig.encodingLength(sig))
    if (!offset) offset = 0
    const oldOffset = offset

    const signature = sig.signature
    if (!Buffer.isBuffer(signature)) {
      throw new Error('Signature must be a Buffer')
    }

    offset += 2 // Leave space for length
    buf.writeUInt16BE(types.toType(sig.typeCovered), offset)
    offset += 2
    buf.writeUInt8(sig.algorithm, offset)
    offset += 1
    buf.writeUInt8(sig.labels, offset)
    offset += 1
    buf.writeUInt32BE(sig.originalTTL, offset)
    offset += 4
    buf.writeUInt32BE(sig.expiration, offset)
    offset += 4
    buf.writeUInt32BE(sig.inception, offset)
    offset += 4
    buf.writeUInt16BE(sig.keyTag, offset)
    offset += 2
    name.encode(sig.signersName, buf, offset)
    offset += name.encode.bytes
    signature.copy(buf, offset, 0, signature.length)
    offset += signature.length

    rrrsig.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rrrsig.encode.bytes - 2, oldOffset)
    return buf
  } as rRRSIGEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    const oldOffset = offset

    const sig: any = {}
    const length = buf.readUInt16BE(offset)
    offset += 2
    sig.typeCovered = types.toString(buf.readUInt16BE(offset))
    offset += 2
    sig.algorithm = buf.readUInt8(offset)
    offset += 1
    sig.labels = buf.readUInt8(offset)
    offset += 1
    sig.originalTTL = buf.readUInt32BE(offset)
    offset += 4
    sig.expiration = buf.readUInt32BE(offset)
    offset += 4
    sig.inception = buf.readUInt32BE(offset)
    offset += 4
    sig.keyTag = buf.readUInt16BE(offset)
    offset += 2
    sig.signersName = name.decode(buf, offset)
    offset += name.decode.bytes
    sig.signature = buf.slice(offset, oldOffset + length + 2)
    offset += sig.signature.length
    rrrsig.decode.bytes = offset - oldOffset
    return sig as rRRSIG
  } as rRRSIGDecode,

  encodingLength: function (sig: rRRSIG) {
    return 20 +
      name.encodingLength(sig.signersName) +
      Buffer.byteLength(sig.signature)
  }
}
rrrsig.encode.bytes = 0
rrrsig.decode.bytes = 0

interface rRP {
  mbox: string;
  txt: string;
}
interface rRPEncode {
  (data: rRP, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rRPDecode {
  (buf: Buffer, offset?: number): rRP
  bytes: number
}
const rrp = {
  encode: function (data: rRP, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rrp.encodingLength(data))
    if (!offset) offset = 0
    const oldOffset = offset

    offset += 2 // Leave space for length
    name.encode(data.mbox || '.', buf, offset)
    offset += name.encode.bytes
    name.encode(data.txt || '.', buf, offset)
    offset += name.encode.bytes
    rrp.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rrp.encode.bytes - 2, oldOffset)
    return buf
  } as rRPEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    const oldOffset = offset

    const data: any = {}
    offset += 2
    data.mbox = name.decode(buf, offset) || '.'
    offset += name.decode.bytes
    data.txt = name.decode(buf, offset) || '.'
    offset += name.decode.bytes
    rrp.decode.bytes = offset - oldOffset
    return data as rRP
  } as rRPDecode,

  encodingLength: function (data: rRP) {
    return 2 + name.encodingLength(data.mbox || '.') + name.encodingLength(data.txt || '.')
  }
}
rrp.encode.bytes = 0
rrp.decode.bytes = 0

interface typebitmapEncode {
  (typelist: string[], buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface typebitmapDecode {
  (buf: Buffer, offset: number | undefined, length: number): string[]
  bytes: number
}
const typebitmap = {
  encode: function (typelist: string[], buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(typebitmap.encodingLength(typelist))
    if (!offset) offset = 0
    const oldOffset = offset

    const typesByWindow: number[][] = []
    for (let i = 0; i < typelist.length; i++) {
      const typeid = types.toType(typelist[i])
      if (typesByWindow[typeid >> 8] === undefined) {
        typesByWindow[typeid >> 8] = []
      }
      typesByWindow[typeid >> 8][(typeid >> 3) & 0x1F] |= 1 << (7 - (typeid & 0x7))
    }

    for (let i = 0; i < typesByWindow.length; i++) {
      if (typesByWindow[i] !== undefined) {
        const windowBuf = Buffer.from(typesByWindow[i])
        buf.writeUInt8(i, offset)
        offset += 1
        buf.writeUInt8(windowBuf.length, offset)
        offset += 1
        windowBuf.copy(buf, offset)
        offset += windowBuf.length
      }
    }

    typebitmap.encode.bytes = offset - oldOffset
    return buf
  } as typebitmapEncode,

  decode: function (buf: Buffer, offset: number | undefined, length: number) {
    if (!offset) offset = 0
    const oldOffset = offset

    const typelist: string[] = []
    while (offset - oldOffset < length) {
      const window = buf.readUInt8(offset)
      offset += 1
      const windowLength = buf.readUInt8(offset)
      offset += 1
      for (let i = 0; i < windowLength; i++) {
        const b = buf.readUInt8(offset + i)
        for (let j = 0; j < 8; j++) {
          if (b & (1 << (7 - j))) {
            const typeid = types.toString((window << 8) | (i << 3) | j)
            typelist.push(typeid)
          }
        }
      }
      offset += windowLength
    }

    typebitmap.decode.bytes = offset - oldOffset
    return typelist
  } as typebitmapDecode,

  encodingLength: function (typelist: string[]) {
    const extents: number[] = []
    for (let i = 0; i < typelist.length; i++) {
      const typeid = types.toType(typelist[i])
      extents[typeid >> 8] = Math.max(extents[typeid >> 8] || 0, typeid & 0xFF)
    }

    let len = 0
    for (let i = 0; i < extents.length; i++) {
      if (extents[i] !== undefined) {
        len += 2 + Math.ceil((extents[i] + 1) / 8)
      }
    }

    return len
  }
}
typebitmap.encode.bytes = 0
typebitmap.decode.bytes = 0

interface rNSEC {
  rrtypes: string[]
  nextDomain: string
}
interface rNSECEncode {
  (record: rNSEC, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rNSECDecode {
  (buf: Buffer, offset?: number): rNSEC
  bytes: number
}
const rnsec = {
  encode: function (record: rNSEC, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rnsec.encodingLength(record))
    if (!offset) offset = 0
    const oldOffset = offset

    offset += 2 // Leave space for length
    name.encode(record.nextDomain, buf, offset)
    offset += name.encode.bytes
    typebitmap.encode(record.rrtypes, buf, offset)
    offset += typebitmap.encode.bytes

    rnsec.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rnsec.encode.bytes - 2, oldOffset)
    return buf
  } as rNSECEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    const oldOffset = offset

    const record: any = {}
    const length = buf.readUInt16BE(offset)
    offset += 2
    record.nextDomain = name.decode(buf, offset)
    offset += name.decode.bytes
    record.rrtypes = typebitmap.decode(buf, offset, length - (offset - oldOffset))
    offset += typebitmap.decode.bytes

    rnsec.decode.bytes = offset - oldOffset
    return record as rNSEC
  } as rNSECDecode,

  encodingLength: function (record: rNSEC) {
    return 2 +
      name.encodingLength(record.nextDomain) +
      typebitmap.encodingLength(record.rrtypes)
  }
}
rnsec.encode.bytes = 0
rnsec.decode.bytes = 0

interface rNSEC3 {
  flags: number
  iterations: number
  algorithm: number
  salt: Buffer
  nextDomain: Buffer
  rrtypes: string[]
}
interface rNSEC3Encode {
  (record: rNSEC3, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rNSEC3Decode {
  (buf: Buffer, offset?: number): rNSEC3
  bytes: number
}
const rnsec3 = {
  encode: function (record: rNSEC3, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rnsec3.encodingLength(record))
    if (!offset) offset = 0
    const oldOffset = offset

    const salt = record.salt
    if (!Buffer.isBuffer(salt)) {
      throw new Error('salt must be a Buffer')
    }

    const nextDomain = record.nextDomain
    if (!Buffer.isBuffer(nextDomain)) {
      throw new Error('nextDomain must be a Buffer')
    }

    offset += 2 // Leave space for length
    buf.writeUInt8(record.algorithm, offset)
    offset += 1
    buf.writeUInt8(record.flags, offset)
    offset += 1
    buf.writeUInt16BE(record.iterations, offset)
    offset += 2
    buf.writeUInt8(salt.length, offset)
    offset += 1
    salt.copy(buf, offset, 0, salt.length)
    offset += salt.length
    buf.writeUInt8(nextDomain.length, offset)
    offset += 1
    nextDomain.copy(buf, offset, 0, nextDomain.length)
    offset += nextDomain.length
    typebitmap.encode(record.rrtypes, buf, offset)
    offset += typebitmap.encode.bytes

    rnsec3.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rnsec3.encode.bytes - 2, oldOffset)
    return buf
  } as rNSEC3Encode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    const oldOffset = offset

    const record: any = {}
    const length = buf.readUInt16BE(offset)
    offset += 2
    record.algorithm = buf.readUInt8(offset)
    offset += 1
    record.flags = buf.readUInt8(offset)
    offset += 1
    record.iterations = buf.readUInt16BE(offset)
    offset += 2
    const saltLength = buf.readUInt8(offset)
    offset += 1
    record.salt = buf.slice(offset, offset + saltLength)
    offset += saltLength
    const hashLength = buf.readUInt8(offset)
    offset += 1
    record.nextDomain = buf.slice(offset, offset + hashLength)
    offset += hashLength
    record.rrtypes = typebitmap.decode(buf, offset, length - (offset - oldOffset))
    offset += typebitmap.decode.bytes

    rnsec3.decode.bytes = offset - oldOffset
    return record as rNSEC3
  } as rNSEC3Decode,

  encodingLength: function (record: rNSEC3) {
    return 8 +
      record.salt.length +
      record.nextDomain.length +
      typebitmap.encodingLength(record.rrtypes)
  }
}
rnsec3.encode.bytes = 0
rnsec3.decode.bytes = 0

interface rDSData {
  digest: Buffer
  keyTag: number
  algorithm: number
  digestType: number
}
interface rDSEncode {
  (digest: rDSData, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rDSDecode {
  (buf: Buffer, offset?: number): rDSData
  bytes: number
}
const rds = {
  encode: function (digest: rDSData, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(rds.encodingLength(digest))
    if (!offset) offset = 0
    const oldOffset = offset

    const digestdata = digest.digest
    if (!Buffer.isBuffer(digestdata)) {
      throw new Error('Digest must be a Buffer')
    }

    offset += 2 // Leave space for length
    buf.writeUInt16BE(digest.keyTag, offset)
    offset += 2
    buf.writeUInt8(digest.algorithm, offset)
    offset += 1
    buf.writeUInt8(digest.digestType, offset)
    offset += 1
    digestdata.copy(buf, offset, 0, digestdata.length)
    offset += digestdata.length

    rds.encode.bytes = offset - oldOffset
    buf.writeUInt16BE(rds.encode.bytes - 2, oldOffset)
    return buf
  } as rDSEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    const oldOffset = offset

    const digest: any = {}
    const length = buf.readUInt16BE(offset)
    offset += 2
    digest.keyTag = buf.readUInt16BE(offset)
    offset += 2
    digest.algorithm = buf.readUInt8(offset)
    offset += 1
    digest.digestType = buf.readUInt8(offset)
    offset += 1
    digest.digest = buf.slice(offset, oldOffset + length + 2)
    offset += digest.digest.length
    rds.decode.bytes = offset - oldOffset
    return digest as rDSData
  } as rDSDecode,

  encodingLength: function (digest: rDSData) {
    return 6 + Buffer.byteLength(digest.digest)
  }
}
rds.encode.bytes = 0
rds.decode.bytes = 0

interface rURIRecord {
  target: string
  priority: number
  weight: number
}
interface rURIEncode {
  (digest: rURIRecord, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface rURIDecode {
  (buf: Buffer, offset?: number): rURIRecord
  bytes: number
}
const ruri = {
  encode: function (record: rURIRecord, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(ruri.encodingLength(record))
    if (!offset) offset = 0
    const oldOffset = offset
    const target = record.target

    buf.writeUInt16BE(4 + target.length, offset)
    offset += 2
    buf.writeUInt16BE(record.priority, offset)
    offset += 2
    buf.writeUInt16BE(record.weight, offset)
    offset += 2
    buf.write(target, offset)
    offset += target.length
    ruri.encode.bytes = offset - oldOffset
    return buf
  } as rURIEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0
    const oldOffset = offset
    const record: any = {}
    var length = buf.readUInt16BE(offset)
    offset += 2
    record.priority = buf.readUInt16BE(offset)
    offset += 2
    record.weight = buf.readUInt16BE(offset)
    offset += 2
    record.target = buf.slice(offset, offset + length - 4).toString()
    offset += length - 4

    ruri.decode.bytes = offset - oldOffset
    return record as rURIRecord
  } as rURIDecode,

  encodingLength: function (record: rURIRecord) {
    return 6 + record.target.length
  }
}
ruri.encode.bytes = 0
ruri.decode.bytes = 0

type RENC = (typeof ra
| typeof rptr
| typeof rcname
| typeof rdname
| typeof rtxt
| typeof rnull
| typeof raaaa
| typeof rsrv
| typeof rhinfo
| typeof rcaa
| typeof rns
| typeof rsoa
| typeof rmx
| typeof ropt
| typeof rdnskey
| typeof rrrsig
| typeof rrp
| typeof rnsec
| typeof rnsec3
| typeof ruri
| typeof rds)
| typeof runknown

function renc (type: string): RENC {
  switch (type.toUpperCase()) {
    case 'A': return ra
    case 'PTR': return rptr
    case 'CNAME': return rcname
    case 'DNAME': return rdname
    case 'TXT': return rtxt
    case 'NULL': return rnull
    case 'AAAA': return raaaa
    case 'SRV': return rsrv
    case 'HINFO': return rhinfo
    case 'CAA': return rcaa
    case 'NS': return rns
    case 'SOA': return rsoa
    case 'MX': return rmx
    case 'OPT': return ropt
    case 'DNSKEY': return rdnskey
    case 'RRSIG': return rrrsig
    case 'RP': return rrp
    case 'NSEC': return rnsec
    case 'NSEC3': return rnsec3
    case 'URI': return ruri
    case 'DS': return rds
  }
  return runknown
}

interface answer {
  name: string;
  type: string;
  udpPayloadSize?: number;
  extendedRcode?: number;
  ednsVersion?: number;
  flags?: number;
  flag_do?: boolean
  options?: rOptionData[];
  class?: string;
  flush?: boolean;
  ttl?: number;
  data?: ReturnType<RENC['decode']>;
}
interface answerEncode {
  (a: answer, buf?: Buffer, offset?: number): Buffer
  bytes: number
}
interface answerDecode {
  (buf: Buffer, offset?: number): answer
  bytes: number
}
const answer = {
  encode: function (a: answer, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(answer.encodingLength(a))
    if (!offset) offset = 0

    const oldOffset = offset

    name.encode(a.name, buf, offset)
    offset += name.encode.bytes

    buf.writeUInt16BE(types.toType(a.type), offset)

    if (a.type.toUpperCase() === 'OPT') {
      if (a.name !== '.') {
        throw new Error('OPT name must be root.')
      }
      buf.writeUInt16BE(a.udpPayloadSize || 4096, offset + 2)
      buf.writeUInt8(a.extendedRcode || 0, offset + 4)
      buf.writeUInt8(a.ednsVersion || 0, offset + 5)
      buf.writeUInt16BE(a.flags || 0, offset + 6)

      offset += 8
      ropt.encode(a.options || [], buf, offset)
      offset += ropt.encode.bytes
    } else {
      let klass = classes.toClass(a.class === undefined ? 'IN' : a.class)
      if (a.flush) klass |= FLUSH_MASK // the 1st bit of the class is the flush bit
      buf.writeUInt16BE(klass, offset + 2)
      buf.writeUInt32BE(a.ttl || 0, offset + 4)

      offset += 8
      const enc = renc(a.type);
      (enc.encode as (arg0: ReturnType<RENC['decode']>, buf?: Buffer, offset?: number) => Buffer)(a.data!, buf, offset)
      offset += enc.encode.bytes
    }

    answer.encode.bytes = offset - oldOffset
    return buf
  } as answerEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    const a: any = {}
    const oldOffset = offset

    a.name = name.decode(buf, offset)
    offset += name.decode.bytes
    a.type = types.toString(buf.readUInt16BE(offset))
    if (a.type === 'OPT') {
      a.udpPayloadSize = buf.readUInt16BE(offset + 2)
      a.extendedRcode = buf.readUInt8(offset + 4)
      a.ednsVersion = buf.readUInt8(offset + 5)
      a.flags = buf.readUInt16BE(offset + 6)
      a.flag_do = ((a.flags >> 15) & 0x1) === 1
      a.options = ropt.decode(buf, offset + 8)
      offset += 8 + ropt.decode.bytes
    } else {
      const klass = buf.readUInt16BE(offset + 2)
      a.ttl = buf.readUInt32BE(offset + 4)

      a.class = classes.toString(klass & NOT_FLUSH_MASK)
      a.flush = !!(klass & FLUSH_MASK)

      const enc = renc(a.type)
      a.data = enc.decode(buf, offset + 8)
      offset += 8 + enc.decode.bytes
    }

    answer.decode.bytes = offset - oldOffset
    return a as answer
  } as answerDecode,

  encodingLength: function (a: answer): number {
    const data = (a.data !== null && a.data !== undefined) ? a.data : a.options!
    return name.encodingLength(a.name) + 8 + (renc(a.type).encodingLength as (data: ReturnType<RENC['decode']>) => number)(data)
  }
}
answer.encode.bytes = 0
answer.decode.bytes = 0

interface Question {
  name: string
  type: string
  class: string
}
interface questionEncode {
  (q: Question, buf?: Buffer, offset?: number): Question
  bytes: number
}
interface questionDecode {
  (buf: Buffer, offset?: number): Question
  bytes: number
}
const question = {
  encode: function (q: Question, buf?: Buffer, offset?: number) {
    if (!buf) buf = Buffer.allocUnsafe(question.encodingLength(q))
    if (!offset) offset = 0

    const oldOffset = offset

    name.encode(q.name, buf, offset)
    offset += name.encode.bytes

    buf.writeUInt16BE(types.toType(q.type), offset)
    offset += 2

    buf.writeUInt16BE(classes.toClass(q.class === undefined ? 'IN' : q.class), offset)
    offset += 2

    question.encode.bytes = offset - oldOffset
    return q
  } as questionEncode,

  decode: function (buf: Buffer, offset?: number) {
    if (!offset) offset = 0

    const oldOffset = offset
    const q: any = {}

    q.name = name.decode(buf, offset)
    offset += name.decode.bytes

    q.type = types.toString(buf.readUInt16BE(offset))
    offset += 2

    q.class = classes.toString(buf.readUInt16BE(offset))
    offset += 2

    const qu = !!((q!.class as any) & QU_MASK)
    if (qu) q.class &= NOT_QU_MASK

    question.decode.bytes = offset - oldOffset
    return q
  } as questionDecode,

  encodingLength: function (q: Question) {
    return name.encodingLength(q.name) + 4
  }
}
question.encode.bytes = 0
question.decode.bytes = 0

interface result {
  id: number;
  type: 'response' | 'query';
  flags: number;
  flag_qr?: boolean;
  opcode?: string;
  flag_aa?: boolean;
  flag_tc?: boolean;
  flag_rd?: boolean;
  flag_ra?: boolean;
  flag_z?: boolean;
  flag_ad?: boolean;
  flag_cd?: boolean;
  rcode?: string;
  questions?: Question[];
  answers?: answer[]
  authorities?: any[]
  additionals?: any[]
}

function encode (result: result, buf?: Buffer, offset?: number) {
  if (!buf) buf = Buffer.allocUnsafe(encodingLength(result))
  if (!offset) offset = 0

  const oldOffset = offset

  if (!result.questions) result.questions = []
  if (!result.answers) result.answers = []
  if (!result.authorities) result.authorities = []
  if (!result.additionals) result.additionals = []

  header.encode(result, buf, offset)
  offset += header.encode.bytes

  offset = encodeList(result.questions, question, buf, offset)
  offset = encodeList(result.answers, answer, buf, offset)
  offset = encodeList(result.authorities, answer, buf, offset)
  offset = encodeList(result.additionals, answer, buf, offset)

  encode.bytes = offset - oldOffset

  return buf
}

encode.bytes = 0

function decode (buf: Buffer, offset?: number): result {
  if (!offset) offset = 0

  const oldOffset = offset
  const result = header.decode(buf, offset)
  offset += header.decode.bytes

  offset = decodeList(result.questions, question, buf, offset)
  offset = decodeList(result.answers, answer, buf, offset)
  offset = decodeList(result.authorities, answer, buf, offset)
  offset = decodeList(result.additionals, answer, buf, offset)

  decode.bytes = offset! - oldOffset

  return result
}

decode.bytes = 0

function encodingLength (result: result) {
  return header.encodingLength() +
    encodingLengthList(result.questions || [], question) +
    encodingLengthList(result.answers || [], answer) +
    encodingLengthList(result.authorities || [], answer) +
    encodingLengthList(result.additionals || [], answer)
}

function streamEncode (result: result) {
  const buf = encode(result)
  const sbuf = Buffer.allocUnsafe(2)
  sbuf.writeUInt16BE(buf.byteLength, 0)
  const combine = Buffer.concat([sbuf, buf])
  streamEncode.bytes = combine.byteLength
  return combine
}

streamEncode.bytes = 0

function streamDecode (sbuf: Buffer) {
  const len = sbuf.readUInt16BE(0)
  if (sbuf.byteLength < len + 2) {
    // not enough data
    return null
  }
  const result = decode(sbuf.slice(2))
  streamDecode.bytes = decode.bytes
  return result
}

streamDecode.bytes = 0

function encodingLengthList (list: (Question | answer | rOptionData)[], enc: typeof question | typeof answer | typeof roption) {
  let len = 0
  for (let i = 0; i < list.length; i++) len += (enc.encodingLength as (arg0: Question | answer | rOptionData) => number)(list[i])
  return len
}

function encodeList (list: (Question | answer | rOptionData)[], enc: typeof question | typeof answer | typeof roption, buf: Buffer, offset: number) {
  for (let i = 0; i < list.length; i++) {
    (enc.encode as (arg0: Question | answer | rOptionData, buf: Buffer | undefined, offset: number | undefined) => Question | Buffer)(list[i], buf, offset)
    offset += enc.encode.bytes
  }
  return offset
}

function decodeList (list: (Question | answer | rOptionData)[], enc: typeof question | typeof answer | typeof roption, buf: Buffer, offset: number) {
  for (let i = 0; i < list.length; i++) {
    list[i] = enc.decode(buf, offset)
    offset += enc.decode.bytes
  }
  return offset
}

export = {
  name,
  txt: rtxt,
  unknown: runknown,
  ns: rns,
  soa: rsoa,
  null: rnull,
  hinfo: rhinfo,
  ptr: rptr,
  cname: rcname,
  dname: rdname,
  srv: rsrv,
  caa: rcaa,
  mx: rmx,
  a: ra,
  aaaa: raaaa,
  option: roption,
  opt: ropt,
  dnskey: rdnskey,
  rrsig: rrrsig,
  rp: rrp,
  nsec: rnsec,
  nsec3: rnsec3,
  ds: rds,
  uri: ruri,
  record: renc,
  answer,
  question,
  AUTHORITATIVE_ANSWER: 1 << 10,
  TRUNCATED_RESPONSE: 1 << 9,
  RECURSION_DESIRED: 1 << 8,
  RECURSION_AVAILABLE: 1 << 7,
  AUTHENTIC_DATA: 1 << 5,
  CHECKING_DISABLED: 1 << 4,
  DNSSEC_OK: 1 << 15,
  encode,
  decode,
  encodingLength,
  streamEncode,
  streamDecode
}
