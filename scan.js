const IPCIDR = require('ip-cidr')
const { Socket } = require('net')
const path = require('path')
const { Semaphore } = require('async-mutex')
const ProgressBar = require('progress')

const mask = process.argv[2]
const port = process.argv[3]
const concurrency = process.argv[4] ? Number(process.argv[4]) : 2000
const timeout = process.argv[5] ? Number(process.argv[5]) : 2000
const semaphore = new Semaphore(concurrency)

const helpMessage = `Error: Missing argument(s).

Signature:
node ${path.basename(__filename)} cidr port [concurrency] [timeout]

Example:
node ${path.basename(__filename)} 10.0.0.0/24 80`

if (mask === undefined || port === undefined) {
  console.error(helpMessage)
  return
}

const isPortOpen = (host, port, timeout) => {
  return semaphore.runExclusive(() => {
    return new Promise(async (resolve, reject) => {
      const socket = new Socket()
      socket.setTimeout(timeout)

      const complete = (state) => {
        resolve({
          host,
          port,
          state,
          localAddress: socket.localAddress,
          localPort: socket.localPort,
          remoteAddress: socket.remoteAddress,
          remotePort: socket.remotePort
        })
        socket.destroy()
      }

      socket.on('connect', () => {
        socket.write("Hello World!", 'utf8')
        complete('connected')
      })
      socket.on('close', () => complete('closed'))
      socket.on('timeout', () => complete('timeout'))
      socket.on('error', () => complete('error'))

      socket.connect(port, host)
    })
  })
}

class ScannerIterator {
  constructor(mask, batchSize = 5000) {
    this.batchSize = batchSize
    this.size = 2 ** (32 - Number(mask.split('/')[1]))
    this.cidr = new IPCIDR(mask)
    this.index = 0
    this.from = 0
    this.ips = this._getIPs()
  }

  _getIPs() {
    return this.cidr.toArray({ from: this.from, limit: this.batchSize })
  }

  _updateIPs() {
    if (this.index > this.ips.length - 1) {
      this.index = 0
      this.from += this.batchSize
      this.ips = this._getIPs()
    }
  }

  next() {
    if (this.from + this.index >= this.size) {
      return { done: true }
    }

    const value = this.ips[this.index]
    this.index += 1

    this._updateIPs()

    return { value }
  }
}

class Scanner {
  constructor(mask, batchSize = 5000) {
    this.mask = mask
    this.batchSize = batchSize
    this.size = 2 ** (32 - Number(mask.split('/')[1]))
    this.cidr = new IPCIDR(mask)
  }

  iterator() {
    return new ScannerIterator(this.mask, this.batchSize)
  }

  *[Symbol.iterator]() {
    const iterator = this.iterator()
    let { value } = iterator.next()
    while (value) {
      yield value;
      value = iterator.next().value
    }
  }

  async forEach(callback, concurrency = 10000) {
    const iterator = this.iterator()
    const promises = {}

    const pool = new Promise((resolve, reject) => {
      const doWork = (index => {
        const { value } = iterator.next()
        if (value) {
          promises[index] = callback(value)
          promises[index].finally(() => doWork(index))
        } else {
          resolve()
        }
      })

      for (let i = 0; i < concurrency; i++) {
        doWork(i)
      }
    })

    // Wait until there is no work left to do
    await pool

    // Wait for all running workers to finish
    await Promise.all(Object.values(promises))
  }
}

(async () => {
  const size = 2 ** (32 - Number(mask.split('/')[1]))
  console.log(`Mask ${mask} includes ${size} IP addresses`)
  console.log(`Checking ${size} addresses on port ${port}`)

  const bar = new ProgressBar(' :current / :total [:bar] :percent :etas :rate/s', {
    total: size,
    incomplete: ' ',
    width: 20,
    clear: true
  })

  let matchCount = 0

  await new Scanner(mask).forEach(async (ip) => {
    const result = await isPortOpen(ip, port, timeout)
    if (result.state === 'connected') {
      bar.interrupt(`${result.host} ${result.state}`)
      matchCount++
    }
    bar.tick()
  }, concurrency)

  if (!matchCount) {
    bar.interrupt("No addresses found")
  }
})().catch(e => console.error(e))

