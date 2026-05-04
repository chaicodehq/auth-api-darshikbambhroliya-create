import { User } from "../models/user.model.js";
import { verifyToken } from "../utils/jwt.js";

/**
 * TODO: Authenticate user using JWT
 *
 * 1. Extract Authorization header from req.headers.authorization
 * 2. Check if header exists and starts with "Bearer "
 *    - If not: return 401 with { error: { message: "No token provided" } }
 * 3. Extract token (split by space and get second part)
 * 4. Verify token using verifyToken(token) - wrap in try/catch
 *    - If invalid: return 401 with { error: { message: "Invalid token" } }
 * 5. Find user by decoded.userId
 *    - If not found: return 401 with { error: { message: "Invalid token" } }
 * 6. Attach user to req.user
 * 7. Call next()
 */
export async function authenticate(req, res, next) {
  try {
    let token;
    if (req.headers.authorization?.startsWith("Bearer")) {
      token = req.headers.authorization.split(" ")[1];
    } else {
      return res.status(401).json({
        error: {
          message: "No token provided",
        },
      });
    }
    try {
      const decoded = verifyToken(token);
      const user = await User.findById(decoded.userId);
      if (!user)
        return res.status(401).json({
          error: { message: "Invalid token" },
        });
      req.user = user;
    } catch (error) {
      return res.status(401).json({
        error: { message: "Invalid token" },
      });
    }
    next();
  } catch (error) {
    return res.status(401).json({ error: { message: "Invalid token" } });
  }
}
