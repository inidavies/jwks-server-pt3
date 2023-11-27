class TokenBucket {
    constructor(tokens, timeUnit) {
      this.tokens = tokens;
      this.timeUnit = timeUnit;
      this.bucket = tokens;
      this.lastCheck = Date.now();
      this.totalTimePassed = 0;
    }
  
    handle() {
      const current = Date.now();
      const timePassed = (current - this.lastCheck) / 1000;
      this.lastCheck = current;
      this.totalTimePassed += timePassed;
  
      this.bucket += timePassed * (this.tokens / this.timeUnit);
      console.log(timePassed)
      console.log(this.bucket)
      console.log(this.totalTimePassed)
      if (this.bucket > this.tokens) {
        this.bucket = this.tokens;
      }
      if (this.bucket < 1) {
        console.log("Packet Dropped");
        return false;
      } else {
        this.bucket -= 1;
        //console.log(this.bucket + " left in bucket");
        console.log("Packet Forwarded");
        return true;
      }
    }
}

// 10 tokens per second
const throttle = new TokenBucket(10, 1);

// Middleware function to apply rate limiting to /auth endpoint
function usetokenBucket(req, res, next) {
    const packetStatus = throttle.handle();
    console.log(packetStatus);
    if (!packetStatus) {
        console.log("Too Many Requests");
        return res.status(429).send('Too Many Requests');
    }
    next();
}

module.exports = usetokenBucket;