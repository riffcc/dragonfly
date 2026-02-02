//! Vector font rendering with proper metrics
//!
//! Scalable outline font with per-character width for correct kerning

use crate::framebuffer;

/// A glyph is defined as a series of strokes (line segments)
/// Each stroke is (x1, y1, x2, y2) in a 0-100 coordinate space
struct Glyph {
    strokes: &'static [(i32, i32, i32, i32)],
    width: i32, // Actual width of this character (0-100 scale)
}

/// Draw a string with the vector font
pub fn draw_string(x: i32, y: i32, s: &str, color: u32, scale: i32, thickness: i32) {
    let mut cx = x;
    for c in s.chars() {
        let glyph = get_glyph(c);
        draw_glyph(cx, y, glyph, color, scale, thickness);
        cx += (glyph.width * scale) / 100;
    }
}

/// Calculate the width of a string
pub fn string_width(s: &str, scale: i32) -> i32 {
    let mut width = 0;
    for c in s.chars() {
        let glyph = get_glyph(c);
        width += (glyph.width * scale) / 100;
    }
    width
}

/// Draw a single glyph
fn draw_glyph(x: i32, y: i32, glyph: &Glyph, color: u32, scale: i32, thickness: i32) {
    for &(x1, y1, x2, y2) in glyph.strokes {
        let px1 = x + (x1 * scale) / 100;
        let py1 = y + (y1 * scale) / 100;
        let px2 = x + (x2 * scale) / 100;
        let py2 = y + (y2 * scale) / 100;
        draw_thick_line(px1, py1, px2, py2, color, thickness);
    }
}

/// Draw a thick line using Bresenham's algorithm with thickness
fn draw_thick_line(x1: i32, y1: i32, x2: i32, y2: i32, color: u32, thickness: i32) {
    let dx = (x2 - x1).abs();
    let dy = (y2 - y1).abs();
    let sx = if x1 < x2 { 1 } else { -1 };
    let sy = if y1 < y2 { 1 } else { -1 };
    let mut err = dx - dy;

    let mut x = x1;
    let mut y = y1;

    loop {
        // Draw a filled circle at each point for thickness
        draw_circle_filled(x, y, thickness / 2, color);

        if x == x2 && y == y2 {
            break;
        }

        let e2 = 2 * err;
        if e2 > -dy {
            err -= dy;
            x += sx;
        }
        if e2 < dx {
            err += dx;
            y += sy;
        }
    }
}

/// Draw a filled circle for line thickness
fn draw_circle_filled(cx: i32, cy: i32, r: i32, color: u32) {
    if r <= 0 {
        if cx >= 0 && cy >= 0 {
            framebuffer::put_pixel(cx as u32, cy as u32, color);
        }
        return;
    }

    for dy in -r..=r {
        for dx in -r..=r {
            if dx * dx + dy * dy <= r * r {
                let px = cx + dx;
                let py = cy + dy;
                if px >= 0 && py >= 0 {
                    framebuffer::put_pixel(px as u32, py as u32, color);
                }
            }
        }
    }
}

/// Get the glyph for a character
fn get_glyph(c: char) -> &'static Glyph {
    match c {
        'A' => &GLYPH_A,
        'B' => &GLYPH_B,
        'C' => &GLYPH_C,
        'D' => &GLYPH_D,
        'E' => &GLYPH_E,
        'F' => &GLYPH_F,
        'G' => &GLYPH_G,
        'H' => &GLYPH_H,
        'I' => &GLYPH_I,
        'J' => &GLYPH_J,
        'K' => &GLYPH_K,
        'L' => &GLYPH_L,
        'M' => &GLYPH_M,
        'N' => &GLYPH_N,
        'O' => &GLYPH_O,
        'P' => &GLYPH_P,
        'Q' => &GLYPH_Q,
        'R' => &GLYPH_R,
        'S' => &GLYPH_S,
        'T' => &GLYPH_T,
        'U' => &GLYPH_U,
        'V' => &GLYPH_V,
        'W' => &GLYPH_W,
        'X' => &GLYPH_X,
        'Y' => &GLYPH_Y,
        'Z' => &GLYPH_Z,
        'a' => &GLYPH_A_LOWER,
        'b' => &GLYPH_B_LOWER,
        'c' => &GLYPH_C_LOWER,
        'd' => &GLYPH_D_LOWER,
        'e' => &GLYPH_E_LOWER,
        'f' => &GLYPH_F_LOWER,
        'g' => &GLYPH_G_LOWER,
        'h' => &GLYPH_H_LOWER,
        'i' => &GLYPH_I_LOWER,
        'j' => &GLYPH_J_LOWER,
        'k' => &GLYPH_K_LOWER,
        'l' => &GLYPH_L_LOWER,
        'm' => &GLYPH_M_LOWER,
        'n' => &GLYPH_N_LOWER,
        'o' => &GLYPH_O_LOWER,
        'p' => &GLYPH_P_LOWER,
        'q' => &GLYPH_Q_LOWER,
        'r' => &GLYPH_R_LOWER,
        's' => &GLYPH_S_LOWER,
        't' => &GLYPH_T_LOWER,
        'u' => &GLYPH_U_LOWER,
        'v' => &GLYPH_V_LOWER,
        'w' => &GLYPH_W_LOWER,
        'x' => &GLYPH_X_LOWER,
        'y' => &GLYPH_Y_LOWER,
        'z' => &GLYPH_Z_LOWER,
        '0' => &GLYPH_0,
        '1' => &GLYPH_1,
        '2' => &GLYPH_2,
        '3' => &GLYPH_3,
        '4' => &GLYPH_4,
        '5' => &GLYPH_5,
        '6' => &GLYPH_6,
        '7' => &GLYPH_7,
        '8' => &GLYPH_8,
        '9' => &GLYPH_9,
        ' ' => &GLYPH_SPACE,
        '.' => &GLYPH_PERIOD,
        ',' => &GLYPH_COMMA,
        '-' => &GLYPH_DASH,
        '!' => &GLYPH_EXCLAIM,
        '?' => &GLYPH_QUESTION,
        ':' => &GLYPH_COLON,
        '(' => &GLYPH_LPAREN,
        ')' => &GLYPH_RPAREN,
        '/' => &GLYPH_SLASH,
        _ => &GLYPH_SPACE,
    }
}

// ============================================================================
// GLYPH DEFINITIONS
// All coordinates are in 0-100 space, with (0,0) at top-left
// Height is 100, width varies per character
// ============================================================================

// Uppercase letters
static GLYPH_A: Glyph = Glyph {
    strokes: &[
        (0, 100, 30, 0),   // Left diagonal
        (30, 0, 60, 100),  // Right diagonal
        (15, 50, 45, 50),  // Crossbar
    ],
    width: 70,
};

static GLYPH_B: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),    // Vertical
        (0, 0, 40, 0),     // Top horizontal
        (40, 0, 50, 15),   // Top curve right
        (50, 15, 50, 35),  // Top curve down
        (50, 35, 40, 50),  // Top curve left
        (0, 50, 40, 50),   // Middle horizontal
        (40, 50, 55, 65),  // Bottom curve right
        (55, 65, 55, 85),  // Bottom curve down
        (55, 85, 40, 100), // Bottom curve left
        (0, 100, 40, 100), // Bottom horizontal
    ],
    width: 65,
};

static GLYPH_C: Glyph = Glyph {
    strokes: &[
        (55, 15, 40, 0),   // Top right
        (40, 0, 15, 0),    // Top
        (15, 0, 0, 15),    // Top left curve
        (0, 15, 0, 85),    // Left side
        (0, 85, 15, 100),  // Bottom left curve
        (15, 100, 40, 100),// Bottom
        (40, 100, 55, 85), // Bottom right
    ],
    width: 60,
};

static GLYPH_D: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),    // Left vertical
        (0, 0, 35, 0),     // Top
        (35, 0, 55, 20),   // Top right curve
        (55, 20, 55, 80),  // Right side
        (55, 80, 35, 100), // Bottom right curve
        (35, 100, 0, 100), // Bottom
    ],
    width: 65,
};

static GLYPH_E: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),   // Vertical
        (0, 0, 50, 0),    // Top
        (0, 50, 40, 50),  // Middle
        (0, 100, 50, 100),// Bottom
    ],
    width: 55,
};

static GLYPH_F: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),   // Vertical
        (0, 0, 50, 0),    // Top
        (0, 50, 40, 50),  // Middle
    ],
    width: 55,
};

static GLYPH_G: Glyph = Glyph {
    strokes: &[
        (55, 15, 40, 0),   // Top right
        (40, 0, 15, 0),    // Top
        (15, 0, 0, 15),    // Top left curve
        (0, 15, 0, 85),    // Left side
        (0, 85, 15, 100),  // Bottom left curve
        (15, 100, 40, 100),// Bottom
        (40, 100, 55, 85), // Bottom right curve
        (55, 85, 55, 50),  // Right side
        (55, 50, 35, 50),  // Crossbar
    ],
    width: 65,
};

static GLYPH_H: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),   // Left vertical
        (50, 0, 50, 100), // Right vertical
        (0, 50, 50, 50),  // Crossbar
    ],
    width: 60,
};

static GLYPH_I: Glyph = Glyph {
    strokes: &[
        (20, 0, 20, 100), // Vertical
        (0, 0, 40, 0),    // Top serif
        (0, 100, 40, 100),// Bottom serif
    ],
    width: 45,
};

static GLYPH_J: Glyph = Glyph {
    strokes: &[
        (40, 0, 40, 80),  // Vertical
        (40, 80, 30, 100),// Curve
        (30, 100, 10, 100),
        (10, 100, 0, 85),
    ],
    width: 50,
};

static GLYPH_K: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),   // Vertical
        (50, 0, 0, 50),   // Upper diagonal
        (0, 50, 50, 100), // Lower diagonal
    ],
    width: 55,
};

static GLYPH_L: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),   // Vertical
        (0, 100, 45, 100),// Bottom
    ],
    width: 50,
};

static GLYPH_M: Glyph = Glyph {
    strokes: &[
        (0, 100, 0, 0),   // Left vertical
        (0, 0, 30, 50),   // Left diagonal
        (30, 50, 60, 0),  // Right diagonal
        (60, 0, 60, 100), // Right vertical
    ],
    width: 70,
};

static GLYPH_N: Glyph = Glyph {
    strokes: &[
        (0, 100, 0, 0),   // Left vertical
        (0, 0, 50, 100),  // Diagonal
        (50, 100, 50, 0), // Right vertical
    ],
    width: 60,
};

static GLYPH_O: Glyph = Glyph {
    strokes: &[
        (15, 0, 40, 0),    // Top
        (40, 0, 55, 15),   // Top right
        (55, 15, 55, 85),  // Right
        (55, 85, 40, 100), // Bottom right
        (40, 100, 15, 100),// Bottom
        (15, 100, 0, 85),  // Bottom left
        (0, 85, 0, 15),    // Left
        (0, 15, 15, 0),    // Top left
    ],
    width: 65,
};

static GLYPH_P: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),    // Vertical
        (0, 0, 40, 0),     // Top
        (40, 0, 50, 15),   // Curve right
        (50, 15, 50, 35),  // Curve down
        (50, 35, 40, 50),  // Curve left
        (40, 50, 0, 50),   // Back to stem
    ],
    width: 60,
};

static GLYPH_Q: Glyph = Glyph {
    strokes: &[
        (15, 0, 40, 0),    // Top
        (40, 0, 55, 15),   // Top right
        (55, 15, 55, 85),  // Right
        (55, 85, 40, 100), // Bottom right
        (40, 100, 15, 100),// Bottom
        (15, 100, 0, 85),  // Bottom left
        (0, 85, 0, 15),    // Left
        (0, 15, 15, 0),    // Top left
        (35, 70, 55, 105), // Tail
    ],
    width: 65,
};

static GLYPH_R: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),    // Vertical
        (0, 0, 40, 0),     // Top
        (40, 0, 50, 15),   // Curve right
        (50, 15, 50, 35),  // Curve down
        (50, 35, 40, 50),  // Curve left
        (40, 50, 0, 50),   // Back to stem
        (25, 50, 50, 100), // Leg
    ],
    width: 60,
};

static GLYPH_S: Glyph = Glyph {
    strokes: &[
        (50, 15, 35, 0),   // Top right
        (35, 0, 15, 0),    // Top
        (15, 0, 0, 15),    // Top left
        (0, 15, 0, 35),    // Upper left
        (0, 35, 15, 50),   // Middle left
        (15, 50, 35, 50),  // Middle
        (35, 50, 50, 65),  // Middle right
        (50, 65, 50, 85),  // Lower right
        (50, 85, 35, 100), // Bottom right
        (35, 100, 15, 100),// Bottom
        (15, 100, 0, 85),  // Bottom left
    ],
    width: 55,
};

static GLYPH_T: Glyph = Glyph {
    strokes: &[
        (0, 0, 50, 0),    // Top
        (25, 0, 25, 100), // Vertical
    ],
    width: 55,
};

static GLYPH_U: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 80),     // Left vertical
        (0, 80, 15, 100),  // Bottom left curve
        (15, 100, 35, 100),// Bottom
        (35, 100, 50, 80), // Bottom right curve
        (50, 80, 50, 0),   // Right vertical
    ],
    width: 60,
};

static GLYPH_V: Glyph = Glyph {
    strokes: &[
        (0, 0, 25, 100),  // Left diagonal
        (25, 100, 50, 0), // Right diagonal
    ],
    width: 55,
};

static GLYPH_W: Glyph = Glyph {
    strokes: &[
        (0, 0, 15, 100),  // Left diagonal
        (15, 100, 30, 40),// Inner left
        (30, 40, 45, 100),// Inner right
        (45, 100, 60, 0), // Right diagonal
    ],
    width: 70,
};

static GLYPH_X: Glyph = Glyph {
    strokes: &[
        (0, 0, 50, 100),  // Diagonal 1
        (50, 0, 0, 100),  // Diagonal 2
    ],
    width: 55,
};

static GLYPH_Y: Glyph = Glyph {
    strokes: &[
        (0, 0, 25, 50),   // Left diagonal
        (50, 0, 25, 50),  // Right diagonal
        (25, 50, 25, 100),// Vertical
    ],
    width: 55,
};

static GLYPH_Z: Glyph = Glyph {
    strokes: &[
        (0, 0, 50, 0),    // Top
        (50, 0, 0, 100),  // Diagonal
        (0, 100, 50, 100),// Bottom
    ],
    width: 55,
};

// Lowercase letters
static GLYPH_A_LOWER: Glyph = Glyph {
    strokes: &[
        (40, 40, 15, 40),  // Top
        (15, 40, 0, 55),   // Top left
        (0, 55, 0, 85),    // Left
        (0, 85, 15, 100),  // Bottom left
        (15, 100, 40, 100),// Bottom
        (40, 40, 40, 100), // Right vertical
    ],
    width: 50,
};

static GLYPH_B_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),    // Stem
        (0, 40, 25, 40),   // Top bowl
        (25, 40, 40, 55),
        (40, 55, 40, 85),
        (40, 85, 25, 100),
        (25, 100, 0, 100),
    ],
    width: 50,
};

static GLYPH_C_LOWER: Glyph = Glyph {
    strokes: &[
        (40, 50, 25, 40),  // Top
        (25, 40, 10, 40),
        (10, 40, 0, 55),
        (0, 55, 0, 85),
        (0, 85, 10, 100),
        (10, 100, 25, 100),
        (25, 100, 40, 90),
    ],
    width: 45,
};

static GLYPH_D_LOWER: Glyph = Glyph {
    strokes: &[
        (40, 0, 40, 100),  // Stem
        (40, 40, 15, 40),
        (15, 40, 0, 55),
        (0, 55, 0, 85),
        (0, 85, 15, 100),
        (15, 100, 40, 100),
    ],
    width: 50,
};

static GLYPH_E_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 70, 40, 70),   // Crossbar
        (40, 70, 40, 55),  // Right up
        (40, 55, 25, 40),  // Top right
        (25, 40, 10, 40),  // Top
        (10, 40, 0, 55),   // Top left
        (0, 55, 0, 85),    // Left
        (0, 85, 15, 100),  // Bottom left
        (15, 100, 30, 100),// Bottom
        (30, 100, 40, 90), // Bottom right
    ],
    width: 50,
};

static GLYPH_F_LOWER: Glyph = Glyph {
    strokes: &[
        (15, 100, 15, 20), // Stem
        (15, 20, 25, 5),   // Top curve
        (25, 5, 35, 0),
        (0, 40, 30, 40),   // Crossbar
    ],
    width: 35,
};

static GLYPH_G_LOWER: Glyph = Glyph {
    strokes: &[
        (40, 40, 15, 40),
        (15, 40, 0, 55),
        (0, 55, 0, 85),
        (0, 85, 15, 100),
        (15, 100, 40, 100),
        (40, 40, 40, 115), // Descender
        (40, 115, 25, 130),
        (25, 130, 5, 125),
    ],
    width: 50,
};

static GLYPH_H_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),    // Left stem
        (0, 50, 20, 40),   // Arch
        (20, 40, 40, 50),
        (40, 50, 40, 100), // Right stem
    ],
    width: 50,
};

static GLYPH_I_LOWER: Glyph = Glyph {
    strokes: &[
        (10, 40, 10, 100), // Stem
        (10, 20, 10, 25),  // Dot
    ],
    width: 25,
};

static GLYPH_J_LOWER: Glyph = Glyph {
    strokes: &[
        (20, 40, 20, 115), // Stem
        (20, 115, 10, 130),// Curve
        (10, 130, 0, 125),
        (20, 20, 20, 25),  // Dot
    ],
    width: 30,
};

static GLYPH_K_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 0, 0, 100),   // Stem
        (35, 40, 0, 70),  // Upper diagonal
        (0, 70, 40, 100), // Lower diagonal
    ],
    width: 45,
};

static GLYPH_L_LOWER: Glyph = Glyph {
    strokes: &[
        (10, 0, 10, 100), // Stem
    ],
    width: 25,
};

static GLYPH_M_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 40, 0, 100),   // Left stem
        (0, 50, 15, 40),   // First arch
        (15, 40, 25, 50),
        (25, 50, 25, 100), // Middle stem
        (25, 50, 40, 40),  // Second arch
        (40, 40, 50, 50),
        (50, 50, 50, 100), // Right stem
    ],
    width: 60,
};

static GLYPH_N_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 40, 0, 100),   // Left stem
        (0, 50, 20, 40),   // Arch
        (20, 40, 40, 50),
        (40, 50, 40, 100), // Right stem
    ],
    width: 50,
};

static GLYPH_O_LOWER: Glyph = Glyph {
    strokes: &[
        (15, 40, 30, 40),  // Top
        (30, 40, 45, 55),
        (45, 55, 45, 85),
        (45, 85, 30, 100),
        (30, 100, 15, 100),
        (15, 100, 0, 85),
        (0, 85, 0, 55),
        (0, 55, 15, 40),
    ],
    width: 55,
};

static GLYPH_P_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 40, 0, 130),   // Stem with descender
        (0, 40, 25, 40),
        (25, 40, 40, 55),
        (40, 55, 40, 85),
        (40, 85, 25, 100),
        (25, 100, 0, 100),
    ],
    width: 50,
};

static GLYPH_Q_LOWER: Glyph = Glyph {
    strokes: &[
        (40, 40, 40, 130), // Stem with descender
        (40, 40, 15, 40),
        (15, 40, 0, 55),
        (0, 55, 0, 85),
        (0, 85, 15, 100),
        (15, 100, 40, 100),
    ],
    width: 50,
};

static GLYPH_R_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 40, 0, 100),   // Stem
        (0, 50, 15, 40),   // Shoulder
        (15, 40, 30, 45),
    ],
    width: 35,
};

static GLYPH_S_LOWER: Glyph = Glyph {
    strokes: &[
        (35, 50, 25, 40),
        (25, 40, 10, 40),
        (10, 40, 0, 50),
        (0, 50, 0, 60),
        (0, 60, 10, 70),
        (10, 70, 25, 70),
        (25, 70, 35, 80),
        (35, 80, 35, 90),
        (35, 90, 25, 100),
        (25, 100, 10, 100),
        (10, 100, 0, 90),
    ],
    width: 45,
};

static GLYPH_T_LOWER: Glyph = Glyph {
    strokes: &[
        (15, 10, 15, 90),  // Stem
        (15, 90, 25, 100), // Foot
        (25, 100, 35, 95),
        (0, 40, 30, 40),   // Crossbar
    ],
    width: 40,
};

static GLYPH_U_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 40, 0, 85),    // Left
        (0, 85, 15, 100),
        (15, 100, 25, 100),
        (25, 100, 40, 85),
        (40, 85, 40, 40),  // Right
        (40, 40, 40, 100), // Right extended
    ],
    width: 50,
};

static GLYPH_V_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 40, 20, 100),
        (20, 100, 40, 40),
    ],
    width: 45,
};

static GLYPH_W_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 40, 10, 100),
        (10, 100, 20, 60),
        (20, 60, 30, 100),
        (30, 100, 40, 40),
    ],
    width: 50,
};

static GLYPH_X_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 40, 35, 100),
        (35, 40, 0, 100),
    ],
    width: 40,
};

static GLYPH_Y_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 40, 20, 80),
        (40, 40, 20, 80),
        (20, 80, 10, 130), // Descender
    ],
    width: 45,
};

static GLYPH_Z_LOWER: Glyph = Glyph {
    strokes: &[
        (0, 40, 35, 40),
        (35, 40, 0, 100),
        (0, 100, 35, 100),
    ],
    width: 40,
};

// Numbers
static GLYPH_0: Glyph = Glyph {
    strokes: &[
        (15, 0, 35, 0),
        (35, 0, 50, 15),
        (50, 15, 50, 85),
        (50, 85, 35, 100),
        (35, 100, 15, 100),
        (15, 100, 0, 85),
        (0, 85, 0, 15),
        (0, 15, 15, 0),
        (10, 80, 40, 20), // Slash
    ],
    width: 60,
};

static GLYPH_1: Glyph = Glyph {
    strokes: &[
        (10, 20, 25, 0),
        (25, 0, 25, 100),
        (10, 100, 40, 100),
    ],
    width: 50,
};

static GLYPH_2: Glyph = Glyph {
    strokes: &[
        (0, 20, 10, 5),
        (10, 5, 35, 0),
        (35, 0, 50, 15),
        (50, 15, 50, 35),
        (50, 35, 0, 100),
        (0, 100, 50, 100),
    ],
    width: 55,
};

static GLYPH_3: Glyph = Glyph {
    strokes: &[
        (0, 10, 15, 0),
        (15, 0, 35, 0),
        (35, 0, 50, 15),
        (50, 15, 50, 35),
        (50, 35, 35, 50),
        (35, 50, 15, 50),
        (35, 50, 50, 65),
        (50, 65, 50, 85),
        (50, 85, 35, 100),
        (35, 100, 15, 100),
        (15, 100, 0, 90),
    ],
    width: 55,
};

static GLYPH_4: Glyph = Glyph {
    strokes: &[
        (35, 100, 35, 0),
        (35, 0, 0, 65),
        (0, 65, 50, 65),
    ],
    width: 55,
};

static GLYPH_5: Glyph = Glyph {
    strokes: &[
        (45, 0, 5, 0),
        (5, 0, 0, 45),
        (0, 45, 30, 45),
        (30, 45, 45, 60),
        (45, 60, 45, 85),
        (45, 85, 30, 100),
        (30, 100, 10, 100),
        (10, 100, 0, 90),
    ],
    width: 55,
};

static GLYPH_6: Glyph = Glyph {
    strokes: &[
        (45, 15, 30, 0),
        (30, 0, 15, 0),
        (15, 0, 0, 15),
        (0, 15, 0, 85),
        (0, 85, 15, 100),
        (15, 100, 30, 100),
        (30, 100, 45, 85),
        (45, 85, 45, 60),
        (45, 60, 30, 45),
        (30, 45, 0, 50),
    ],
    width: 55,
};

static GLYPH_7: Glyph = Glyph {
    strokes: &[
        (0, 0, 50, 0),
        (50, 0, 20, 100),
    ],
    width: 55,
};

static GLYPH_8: Glyph = Glyph {
    strokes: &[
        (15, 0, 35, 0),
        (35, 0, 50, 12),
        (50, 12, 50, 38),
        (50, 38, 35, 50),
        (35, 50, 15, 50),
        (15, 50, 0, 38),
        (0, 38, 0, 12),
        (0, 12, 15, 0),
        (15, 50, 0, 62),
        (0, 62, 0, 88),
        (0, 88, 15, 100),
        (15, 100, 35, 100),
        (35, 100, 50, 88),
        (50, 88, 50, 62),
        (50, 62, 35, 50),
    ],
    width: 55,
};

static GLYPH_9: Glyph = Glyph {
    strokes: &[
        (45, 50, 15, 55),
        (15, 55, 0, 40),
        (0, 40, 0, 15),
        (0, 15, 15, 0),
        (15, 0, 30, 0),
        (30, 0, 45, 15),
        (45, 15, 45, 85),
        (45, 85, 30, 100),
        (30, 100, 15, 100),
        (15, 100, 0, 85),
    ],
    width: 55,
};

// Punctuation and symbols
static GLYPH_SPACE: Glyph = Glyph {
    strokes: &[],
    width: 35,
};

static GLYPH_PERIOD: Glyph = Glyph {
    strokes: &[
        (5, 90, 10, 90),
        (10, 90, 10, 100),
        (10, 100, 5, 100),
        (5, 100, 5, 90),
    ],
    width: 25,
};

static GLYPH_COMMA: Glyph = Glyph {
    strokes: &[
        (10, 90, 10, 100),
        (10, 100, 5, 115),
    ],
    width: 25,
};

static GLYPH_DASH: Glyph = Glyph {
    strokes: &[
        (0, 50, 35, 50),
    ],
    width: 45,
};

static GLYPH_EXCLAIM: Glyph = Glyph {
    strokes: &[
        (10, 0, 10, 70),
        (10, 90, 10, 100),
    ],
    width: 25,
};

static GLYPH_QUESTION: Glyph = Glyph {
    strokes: &[
        (0, 15, 10, 0),
        (10, 0, 30, 0),
        (30, 0, 40, 15),
        (40, 15, 40, 35),
        (40, 35, 20, 55),
        (20, 55, 20, 70),
        (20, 90, 20, 100),
    ],
    width: 50,
};

static GLYPH_COLON: Glyph = Glyph {
    strokes: &[
        (10, 35, 10, 45),
        (10, 85, 10, 95),
    ],
    width: 25,
};

static GLYPH_LPAREN: Glyph = Glyph {
    strokes: &[
        (20, 0, 5, 25),
        (5, 25, 5, 75),
        (5, 75, 20, 100),
    ],
    width: 30,
};

static GLYPH_RPAREN: Glyph = Glyph {
    strokes: &[
        (5, 0, 20, 25),
        (20, 25, 20, 75),
        (20, 75, 5, 100),
    ],
    width: 30,
};

static GLYPH_SLASH: Glyph = Glyph {
    strokes: &[
        (30, 0, 0, 100),
    ],
    width: 40,
};
