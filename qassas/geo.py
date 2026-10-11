"""Name the nearest Kuwaiti area for a GPS fix found in evidence.

The coordinates are approximate area centres chosen for teaching. They are
good enough to say a photo was taken in Salmiya rather than Jahra, but a
report should confirm a location on a proper map and say how it was checked.
"""

import math

AREAS = [
    ("Kuwait City", "مدينة الكويت", 29.3759, 47.9774),
    ("Sharq", "شرق", 29.3833, 47.9967),
    ("Mubarakiya", "المباركية", 29.3712, 47.9746),
    ("Shuwaikh", "الشويخ", 29.3500, 47.9300),
    ("Salmiya", "السالمية", 29.3346, 48.0715),
    ("Hawalli", "حولي", 29.3328, 48.0286),
    ("Jabriya", "الجابرية", 29.3180, 48.0200),
    ("Farwaniya", "الفروانية", 29.2775, 47.9580),
    ("Kuwait International Airport", "مطار الكويت الدولي", 29.2266, 47.9689),
    ("Sabah Al Salem", "صباح السالم", 29.2560, 48.0680),
    ("Mubarak Al Kabeer", "مبارك الكبير", 29.1850, 48.0600),
    ("Ahmadi", "الأحمدي", 29.0769, 48.0838),
    ("Fahaheel", "الفحيحيل", 29.0825, 48.1303),
    ("Jahra", "الجهراء", 29.3375, 47.6581),
    ("Subiya", "الصبية", 29.5600, 47.8500),
    ("Failaka Island", "جزيرة فيلكا", 29.4386, 48.3333),
    ("Wafra", "الوفرة", 28.6390, 47.9300),
    ("Khiran", "الخيران", 28.6600, 48.3800),
    ("Abdali", "العبدلي", 29.9700, 47.7200),
]


def distance_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def nearest(lat, lon):
    """Return the nearest area with its distance, or None when the point is outside Kuwait's area."""
    best = min(AREAS, key=lambda a: distance_km(lat, lon, a[2], a[3]))
    km = distance_km(lat, lon, best[2], best[3])
    if km > 60:
        return None
    return {"en": best[0], "ar": best[1], "km": round(km, 2)}
