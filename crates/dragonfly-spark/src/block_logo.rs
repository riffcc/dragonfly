//! Scalable block logo renderer
//!
//! Renders the DRAGONFLY ASCII art logo at any resolution

use crate::framebuffer;

/// The logo as a bitmap - each row is a slice of (col, width) runs of filled pixels
/// This is more compact than storing every cell
/// Coordinates are in a 74-wide x 6-tall grid
const LOGO_ROWS: &[&[(u8, u8)]] = &[
    // Row 0:  ██████╗ ██████╗  █████╗  ██████╗  ██████╗ ███╗   ██╗███████╗██╗  ██╗   ██╗
    &[(1,6), (9,6), (17,5), (24,6), (32,6), (39,3), (45,2), (48,7), (56,2), (60,2), (66,2)],
    // Row 1:  ██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗████╗  ██║██╔════╝██║  ╚██╗ ██╔╝
    &[(1,2), (6,2), (9,2), (14,2), (17,2), (22,2), (25,2), (32,2), (38,2), (41,4), (47,2), (50,2), (56,2), (61,2), (65,2)],
    // Row 2:  ██║  ██║██████╔╝███████║██║  ███╗██║   ██║██╔██╗ ██║█████╗  ██║   ╚████╔╝
    &[(1,2), (6,2), (9,6), (17,7), (25,2), (30,3), (34,2), (40,2), (44,2), (47,2), (50,2), (53,5), (60,2), (66,4)],
    // Row 3:  ██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║██╔══╝  ██║    ╚██╔╝
    &[(1,2), (6,2), (9,2), (14,2), (17,2), (22,2), (25,2), (31,2), (34,2), (40,2), (44,2), (48,2), (50,2), (53,2), (60,2), (67,2)],
    // Row 4:  ██████╔╝██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██║     ███████╗██║
    &[(1,6), (9,2), (14,2), (17,2), (22,2), (26,6), (34,6), (41,2), (45,4), (50,2), (56,7), (64,2)],
    // Row 5:  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝
    &[], // Shadow row - we'll skip or render differently
];

/// Logo dimensions in grid cells
const LOGO_WIDTH: u32 = 74;
const LOGO_HEIGHT: u32 = 5; // 5 main rows (skip shadow row)

/// Draw the block logo centered at the given Y position
/// Automatically scales to fit the screen width with padding
pub fn draw_logo(screen_width: u32, y: u32, color: u32, shadow_color: u32) {
    // Calculate cell size to fit logo with 10% padding on each side
    let available_width = screen_width * 80 / 100; // 80% of screen
    let cell_width = available_width / LOGO_WIDTH;
    let cell_height = cell_width * 2; // Taller cells look better for block letters

    // Minimum cell size of 4 pixels
    let cell_width = cell_width.max(4);
    let cell_height = cell_height.max(8);

    // Calculate actual logo size and center it
    let logo_pixel_width = LOGO_WIDTH * cell_width;
    let x_offset = (screen_width - logo_pixel_width) / 2;

    // Draw shadow first (offset down and right)
    let shadow_offset = (cell_width / 3).max(2);
    for (row_idx, row) in LOGO_ROWS.iter().take(5).enumerate() {
        let row_y = y + (row_idx as u32 * cell_height) + shadow_offset;
        for &(col, width) in *row {
            let cell_x = x_offset + (col as u32 * cell_width) + shadow_offset;
            framebuffer::fill_rect(cell_x, row_y, width as u32 * cell_width, cell_height, shadow_color);
        }
    }

    // Draw main logo
    for (row_idx, row) in LOGO_ROWS.iter().take(5).enumerate() {
        let row_y = y + (row_idx as u32 * cell_height);
        for &(col, width) in *row {
            let cell_x = x_offset + (col as u32 * cell_width);
            framebuffer::fill_rect(cell_x, row_y, width as u32 * cell_width, cell_height, color);
        }
    }
}

/// Get the height of the logo at current scale for a given screen width
pub fn logo_height(screen_width: u32) -> u32 {
    let available_width = screen_width * 80 / 100;
    let cell_width = (available_width / LOGO_WIDTH).max(4);
    let cell_height = (cell_width * 2).max(8);
    LOGO_HEIGHT * cell_height
}
