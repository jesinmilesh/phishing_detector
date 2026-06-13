import os
from PIL import Image, ImageDraw

def generate_logo_files():
    logo_dir = "static/assets/logo"
    os.makedirs(logo_dir, exist_ok=True)
    
    # ----------------------------------------------------
    # 1. Create SVG Files
    # ----------------------------------------------------
    svg_content = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100">
    <defs>
        <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#0ea5e9" />
            <stop offset="100%" stop-color="#0284c7" />
        </linearGradient>
    </defs>
    <path d="M50 10 L85 25 L85 60 C85 78 70 90 50 95 C30 90 15 78 15 60 L15 25 Z" fill="url(#shieldGrad)" />
    <circle cx="50" cy="35" r="5" fill="#ffffff" />
    <circle cx="35" cy="50" r="4" fill="#ffffff" opacity="0.8" />
    <circle cx="65" cy="50" r="4" fill="#ffffff" opacity="0.8" />
    <circle cx="50" cy="65" r="5" fill="#ffffff" />
    <path d="M50 35 L35 50 L50 65 L65 50 Z" stroke="#ffffff" stroke-width="2.5" fill="none" stroke-linejoin="round" opacity="0.7" />
    <path d="M50 35 L50 65" stroke="#ffffff" stroke-width="2.5" opacity="0.7" />
    <path d="M35 50 L65 50" stroke="#ffffff" stroke-width="2.5" opacity="0.7" />
</svg>"""

    svg_dark_content = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100">
    <path d="M50 10 L85 25 L85 60 C85 78 70 90 50 95 C30 90 15 78 15 60 L15 25 Z" fill="#ffffff" />
    <circle cx="50" cy="35" r="5" fill="#060913" />
    <circle cx="35" cy="50" r="4" fill="#060913" opacity="0.8" />
    <circle cx="65" cy="50" r="4" fill="#060913" opacity="0.8" />
    <circle cx="50" cy="65" r="5" fill="#060913" />
    <path d="M50 35 L35 50 L50 65 L65 50 Z" stroke="#060913" stroke-width="2.5" fill="none" stroke-linejoin="round" opacity="0.7" />
    <path d="M50 35 L50 65" stroke="#060913" stroke-width="2.5" opacity="0.7" />
    <path d="M35 50 L65 50" stroke="#060913" stroke-width="2.5" opacity="0.7" />
</svg>"""

    svg_light_content = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100">
    <path d="M50 10 L85 25 L85 60 C85 78 70 90 50 95 C30 90 15 78 15 60 L15 25 Z" fill="#0f172a" />
    <circle cx="50" cy="35" r="5" fill="#ffffff" />
    <circle cx="35" cy="50" r="4" fill="#ffffff" opacity="0.8" />
    <circle cx="65" cy="50" r="4" fill="#ffffff" opacity="0.8" />
    <circle cx="50" cy="65" r="5" fill="#ffffff" />
    <path d="M50 35 L35 50 L50 65 L65 50 Z" stroke="#ffffff" stroke-width="2.5" fill="none" stroke-linejoin="round" opacity="0.7" />
    <path d="M50 35 L50 65" stroke="#ffffff" stroke-width="2.5" opacity="0.7" />
    <path d="M35 50 L65 50" stroke="#ffffff" stroke-width="2.5" opacity="0.7" />
</svg>"""

    with open(os.path.join(logo_dir, "logo.svg"), "w") as f:
        f.write(svg_content)
    with open(os.path.join(logo_dir, "logo-dark.svg"), "w") as f:
        f.write(svg_dark_content)
    with open(os.path.join(logo_dir, "logo-light.svg"), "w") as f:
        f.write(svg_light_content)

    # ----------------------------------------------------
    # 2. Create PNG Logo & Favicon using Pillow
    # ----------------------------------------------------
    # We will programmatically draw the same shield in Pillow
    img = Image.new("RGBA", (512, 512), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Coordinates for shield: 50 10 -> L85 25 -> L85 60 -> C85 78 70 90 50 95 -> C30 90 15 78 15 60 -> 15 25
    # Rescaled to 512x512
    # Vertices:
    # Top center: (256, 51)
    # Right top: (435, 128)
    # Right curve start: (435, 307)
    # Bottom center: (256, 486)
    # Left curve start: (77, 307)
    # Left top: (77, 128)
    shield_pts = [
        (256, 51), (435, 128), (435, 307), (256, 486), (77, 307), (77, 128)
    ]
    
    # Draw Shield fill
    draw.polygon(shield_pts, fill=(14, 165, 233, 255))
    
    # Draw inner lines
    draw.line([(256, 179), (179, 256), (256, 333), (333, 256), (256, 179)], fill=(255, 255, 255, 180), width=10)
    draw.line([(256, 179), (256, 333)], fill=(255, 255, 255, 180), width=10)
    draw.line([(179, 256), (333, 256)], fill=(255, 255, 255, 180), width=10)
    
    # Draw nodes
    draw.ellipse([(240, 163), (272, 195)], fill=(255, 255, 255, 255))
    draw.ellipse([(165, 242), (193, 270)], fill=(255, 255, 255, 255))
    draw.ellipse([(319, 242), (347, 270)], fill=(255, 255, 255, 255))
    draw.ellipse([(240, 317), (272, 349)], fill=(255, 255, 255, 255))
    
    img.save(os.path.join(logo_dir, "logo.png"), "PNG")
    
    # Generate favicon (32x32)
    fav = img.resize((32, 32), Image.Resampling.LANCZOS)
    fav.save(os.path.join(logo_dir, "favicon.ico"), format="ICO")
    print("Logos successfully created in static/assets/logo/")

if __name__ == "__main__":
    generate_logo_files()
