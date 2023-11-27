const { RateLimiterMemory } = require('rate-limiter-flexible');

// Rate limiter
const opts = {
  points: 10, // Max requests
  duration: 1, // Per second
};
const rateLimiter = new RateLimiterMemory(opts);

// Middleware for limitining requests
const rateLimiterMiddleware = (req, res, next) => {
  rateLimiter.consume(req.ip)
    .then(() => {
      next();
    })
    .catch(() => {
      return res.status(429).send('Too Many Requests');
    });
};
module.exports = rateLimiterMiddleware;