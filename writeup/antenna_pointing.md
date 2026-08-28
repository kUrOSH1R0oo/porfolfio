---
title: "Antenna Pointing"
date: 08-28-2026
excerpt: 'Hack The Box CTF: Satellite Category'
cover: ../uploads/cover_antenna.jpg
tags: SGP4 Orbital Propagation, Topocentric Coordinate Transformation, Binary Search Refinement
---

Welcome back to another writeup! Hack The Box recently introduced a brand-new category to their CTF challenges: **Satellite**! This is one of the most interesting categories I've encountered so far because, instead of dealing with the usual web applications, binaries, networks, or cryptography, we're now dealing with **satellite communications, orbital mechanics, TLEs, ground stations, and antenna tracking**.

For this writeup, I'll walk through how I solved one of the newest challenges in the Satellite category: **Antenna Pointing**. I've tried to break every concept down from first principles, so even if you've never touched orbital mechanics before, you should be able to follow the whole solve.

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FfpWRQjpNgnwa41ba9RgR%252FScreenshot%2520%283161%29.png%3Falt%3Dmedia%26token%3Db162f9cd-a125-4c97-b6b0-3ddc3323e48c&width=768&dpr=3&quality=100&sign=6c73d382ea7b0b079206527f101d5fa5&sv=3)

At first glance, the challenge might look intimidating because it involves **Two-Line Element sets (TLEs)** and determining the position of a satellite in the sky. Once the underlying concepts are understood, though, the problem becomes very manageable — it's really just "look up where the satellite is, then do some geometry."

## What Are We Actually Being Asked to Do?

The objective of the challenge is to:

1. Take the orbital information provided by a **TLE**.
2. Combine it with the coordinates of a **ground control station**.
3. Determine the satellite's **next contact window** (the period during which it's visible).
4. Calculate exactly where the antenna needs to be pointed during the **first 60 seconds** of that window.

For every one of those 60 seconds, we need to calculate two values:

* **Elevation** — how high the satellite is above the horizon, in degrees.
* **Azimuth** — the compass direction the antenna should point, measured clockwise from north.

The challenge defines "visible" as **elevation above 30°**. So the very first thing we need to figure out is: *when does the satellite next climb above 30° elevation?* Once we know that moment, we track the satellite second-by-second for one minute and report the results in this format:

```text
elevation:azimuth
```

For example:

```text
30.0033:238.6166
```

This means the satellite is about **30° above the horizon**, and the antenna needs to point toward an **azimuth of about 238.6°** (a bit west of south).

## Concept 1: Elevation — "How High Do I Tilt the Dish?"

Elevation answers a simple question: *if I'm standing at the ground station and I look toward the satellite, how far up from flat ground do I have to tilt my head?*

* `0°` → the satellite is sitting right on the horizon — you'd have to look sideways to see it.
* `30°` → the minimum angle this challenge considers "visible." Anything lower is considered blocked by terrain, atmosphere, or simply too low to reliably track.
* `45°` → the satellite is roughly halfway between the horizon and straight up.
* `90°` → the satellite is directly overhead.

A cross-section view makes this intuitive:

```text
                                    ● Satellite
                                   /|
                                  / |
                                 /  |
                                /   |
                               /    | (this vertical gap is
                              /     |  irrelevant — elevation
                             /      |  only cares about the angle)
                            /       |
                           / angle  |
     Ground Station ●─────●─────────┴──────────────── Horizon (0°)
                    \____/
                  elevation angle
```

So elevation is purely an **angle**, not a distance. A satellite that's very close but low on the horizon has low elevation; a satellite that's far away but nearly overhead has high elevation.

## Concept 2: Azimuth — "Which Way Do I Turn?"

Elevation tells us how far up to tilt. Azimuth tells us which horizontal direction to face — think of it as a compass bearing, always measured **clockwise from true north**.

```text
                       North (0° / 360°)
                              ↑
                              |
                              |
      West (270°) ←──────────●──────────→ East (90°)
                              |
                              |
                              ↓
                       South (180°)
```

A few reference points:

| Azimuth | Compass direction |
|---------|--------------------|
| 0°      | North              |
| 90°     | East               |
| 180°    | South              |
| 270°    | West               |

So decoding our earlier example:

```text
30.0033:238.6166
   │        │
   │        └── Azimuth  → point ~238.6° clockwise from north
   │                        (between south and west)
   └─────────── Elevation → tilt the dish ~30° above flat ground
```

Together, elevation + azimuth fully describe a direction in 3D space from the observer's point of view — exactly what a physical antenna needs in order to be pointed at a satellite.

## Concept 3: Finding the Contact Window

A satellite doesn't sit still — it's constantly moving along its orbit, so its elevation as seen from our ground station rises and falls over time, tracing something like a hill:

```text
Elevation (°)
   90 ┤                              ╭────╮
      │                           ╭──╯    ╰──╮
   75 ┤                        ╭──╯          ╰──╮
      │                      ╭─╯                ╰─╮
   60 ┤                    ╭─╯                    ╰─╮
      │                  ╭─╯                        ╰─╮
   45 ┤                ╭─╯                            ╰─╮
      │              ╭─╯                                ╰─╮
   30 ┤┄┄┄┄┄┄┄┄┄┄┄┄●┄┄╯┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄●┄┄┄┄  ← 30° threshold
      │           ╱                                        ╲
   15 ┤         ╭╯                                          ╰╮
      │       ╭─╯                                              ╰─╮
    0 ┼─────╯──────────────────────────────────────────────────────╰──▶ Time
              ▲                                                ▲
         Contact starts                                  Contact ends
       (crosses 30° rising)                          (crosses 30° falling)
```

We only care about the **rising** crossing — the first moment the satellite climbs from below 30° to above 30°. That timestamp becomes `T`, the start of our 60-second tracking window. From there we just need:

```text
T, T+1s, T+2s, T+3s, ... , T+59s
```

and for each of those 60 timestamps, an elevation/azimuth pair:

```text
             Contact Window Begins (T)
                       │
                       ▼
        ┌───────────────────────────────┐
        │   60 seconds of tracking       │
        └───────────────────────────────┘
          │     │     │            │
          ▼     ▼     ▼            ▼
          T   T+1s  T+2s   ...   T+59s
          │     │     │            │
          ▼     ▼     ▼            ▼
       El/Az  El/Az  El/Az  ...  El/Az
```

That's why the final submission always contains exactly **60** `elevation:azimuth` pairs.

## Concept 4: What's Inside a TLE?

The challenge gives us a **Two-Line Element set (TLE)** — a compact, standardized text format used since the 1960s to describe the orbit of any Earth-orbiting object (satellites, space stations, even debris):

```text
DIGITWIN HTB
1 01337U 00000A   262418683102+.00000000  00000-0  10730-4 0 985    7
2 01337  97.8502 235.0065 0002677  18.0479   1.4401 15.04120316409375
```

Packed into those two dense lines is everything needed to describe the shape, tilt, and speed of the orbit:

| Parameter | What it tells us |
|---|---|
| Inclination | How tilted the orbital plane is relative to Earth's equator |
| Eccentricity | How circular vs. elongated (elliptical) the orbit is |
| Right ascension of ascending node | Where the orbit crosses the equator, going north |
| Argument of perigee | Where in the orbit the satellite is closest to Earth |
| Mean anomaly | Where the satellite currently is along its orbit |
| Mean motion | How many orbits it completes per day |
| Epoch | The reference time all of the above is measured from |

We don't have to manually crunch any of this orbital math ourselves — that's exactly the job of the **SGP4** propagation model (used here via the `sgp4` Python library, though the same math underlies tools like **Skyfield**). SGP4 takes a TLE and a target time, and hands back the satellite's exact 3D position at that moment:

```text
        TLE                (orbit description)
         │
         ▼
  Orbital elements          (inclination, eccentricity, etc.)
         │
         ▼
   SGP4 propagation         (the actual physics/math engine)
         │
         ▼
  Satellite position        (x, y, z coordinates at time T)
```

## Concept 5: Why the Ground Station's Coordinates Matter

The challenge also provides a ground station location:

```text
Station location:
(Lat,Long): -27.139650885157362, 38.380733761146864
```

It's tempting to think "we already have the satellite's position, isn't that enough?" — but it isn't. Elevation and azimuth are **observer-relative**: the exact same satellite, at the exact same moment, will appear in a completely different part of the sky depending on where you're standing on Earth.

```text
                              ● Satellite
                            ⟋   ⟍
                          ⟋       ⟍
                        ⟋           ⟍
                      ⟋               ⟍
                    ●                   ●
               Station A             Station B
          (sees it low, in            (sees it high,
           the northeast)              nearly overhead)
```

So the calculation genuinely needs both pieces of information:

```text
Satellite's orbital position  +  Observer's location on Earth
                     │
                     ▼
        Direction the antenna must point
              (elevation + azimuth)
```

## Concept 6: From Orbit to Antenna Direction (Putting It Together)

Here's the full pipeline that turns raw orbital data into a usable pointing direction:

```text
   TLE ──▶ SGP4 propagation ──▶ Satellite position (at time T)
                                          │
                     Ground station ──────┤
                     coordinates          │
                                          ▼
                          Observer-relative position
                       ("where is the satellite relative
                            to me, right now?")
                                          │
                                          ▼
                         Topocentric (local) coordinates
                                          │
                             ┌────────────┴────────────┐
                             ▼                          ▼
                         Elevation                  Azimuth
                             │                          │
                             └────────────┬─────────────┘
                                          ▼
                                 elevation:azimuth
```

Conceptually (using a library like Skyfield), this looks like:

```python
difference = satellite - station
topocentric = difference.at(t)

altitude, azimuth, distance = topocentric.altaz()
```

`altitude.degrees` gives us elevation, and `azimuth.degrees` gives us azimuth — exactly the two numbers the challenge wants.

## Building the Solver From Scratch

Rather than relying on a batteries-included library like Skyfield, my solution implements the coordinate math manually. It's more code, but it makes every transformation explicit — which is genuinely the best way to *understand* what's going on rather than just calling a black-box function. Here's the breakdown of what each piece does and why it's needed:

**1. Converting a timestamp into a Julian Date.** Orbital mechanics equations are built around Julian Dates (a continuous day-count used in astronomy) rather than calendar dates, so every timestamp first gets converted.

**2. Computing Greenwich Mean Sidereal Time (GMST).** SGP4 outputs the satellite's position in an *Earth-centered inertial* frame — i.e., fixed relative to the distant stars, not to the spinning Earth. Since our ground station rotates with the Earth, we need to know exactly how much the Earth has rotated since a reference point, which is what GMST tells us.

**3. Rotating from inertial to Earth-fixed coordinates (ECI → ECEF).** Using that GMST angle, we rotate the satellite's position so it's expressed in a frame that rotates along with the Earth (and therefore with our ground station).

**4. Converting the ground station's latitude/longitude into the same Earth-fixed coordinate system (ECEF).** This uses the WGS84 ellipsoid model (the same reference model GPS uses) to account for the fact that Earth isn't a perfect sphere.

**5. Computing the local East-North-Up (topocentric) vector.** With both the satellite and the station expressed in the same coordinate system, we subtract to get a vector pointing from the station to the satellite, then rotate that vector into "east/north/up" terms relative to the station — the natural frame for describing "how high" and "which way."

**6. Extracting elevation and azimuth.** Elevation comes from the "up" component versus the total distance (an arcsine), and azimuth comes from the east/north components (an arctangent).

**7. Searching for the 30° crossing.** Starting from right now, the solver steps forward one second at a time, checking elevation until it finds a second where elevation crosses from below 30° to above 30°. To pin down that crossing more precisely than a whole second, it then uses **binary search (bisection)**: repeatedly halving the time interval between the "too low" and "too high" samples until it converges on the exact crossing moment.

**8. Generating the 60-second window.** Once the crossing time is known, the solver simply loops 60 times, calculating elevation and azimuth for each second and formatting the result as `elevation:azimuth`.

**9. Talking to the challenge server.** The script opens a raw TCP socket to the challenge instance, parses the TLE and station coordinates out of the server's text prompt using regular expressions, computes the answer, and sends it back — repeating for all three satellites the challenge asks about before it hands over the flag.

Here's the full script:

```python
#!/usr/bin/env python3
import socket
import re
import math
from datetime import datetime, timezone, timedelta
from sgp4.api import Satrec

HOST = "154.57.164.82"
PORT = 32505
MIN_ELEVATION = 30.0
PROMPT = "Where will it be next?>"

# =========================================================
# TCP RECEIVE BUFFER
# =========================================================
class BufferedSocket:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = ""
    def recv_until(self, marker):
        """Receive until marker is present. Keeps extra bytes after marker in self.buffer."""
        while marker not in self.buffer:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                raise RuntimeError("Socket timeout while waiting for server")
            if not chunk:
                if self.buffer:
                    data = self.buffer
                    self.buffer = ""
                    return data
                raise RuntimeError("Server closed connection")
            self.buffer += chunk.decode(errors="ignore")
        index = self.buffer.index(marker)
        end = index + len(marker)
        data = self.buffer[:end]
        self.buffer = self.buffer[end:]
        return data

# =========================================================
# TIME / JULIAN DATE
# =========================================================
def datetime_to_jd(dt):
    """Convert timezone-aware datetime to Julian Date."""
    dt = dt.astimezone(timezone.utc)
    return dt.timestamp() / 86400.0 + 2440587.5

def gmst(jd):
    """Greenwich Mean Sidereal Time."""
    T = (jd - 2451545.0) / 36525.0
    theta = (280.46061837 + 360.98564736629 * (jd - 2451545.0)
             + 0.000387933 * T * T - (T ** 3) / 38710000.0)
    return math.radians(theta % 360.0)

# =========================================================
# GROUND STATION
# =========================================================
def observer_ecef(lat_deg, lon_deg, altitude_m=0.0):
    """WGS84 geodetic coordinates -> ECEF kilometers."""
    lat, lon = math.radians(lat_deg), math.radians(lon_deg)
    a, f = 6378.137, 1.0 / 298.257223563
    e2 = f * (2.0 - f)
    sin_lat, cos_lat = math.sin(lat), math.cos(lat)
    N = a / math.sqrt(1.0 - e2 * sin_lat * sin_lat)
    h = altitude_m / 1000.0
    x = (N + h) * cos_lat * math.cos(lon)
    y = (N + h) * cos_lat * math.sin(lon)
    z = (N * (1.0 - e2) + h) * sin_lat
    return x, y, z

# =========================================================
# SATELLITE ECEF
# =========================================================
def satellite_ecef(sat, dt):
    """SGP4 ECI -> ECEF. Returns kilometers."""
    jd = datetime_to_jd(dt)
    jd_int, jd_frac = math.floor(jd), jd - math.floor(jd)
    error, position, velocity = sat.sgp4(jd_int, jd_frac)
    if error != 0:
        raise RuntimeError(f"SGP4 error code: {error}")
    x, y, z = position
    theta = gmst(jd)
    c, s = math.cos(theta), math.sin(theta)
    xe = x * c + y * s
    ye = -x * s + y * c
    ze = z
    return xe, ye, ze

# =========================================================
# AZIMUTH / ELEVATION
# =========================================================
def look_angles(sat, station_lat, station_lon, station, dt):
    """Calculate altitude/elevation and azimuth."""
    sx, sy, sz = satellite_ecef(sat, dt)
    ox, oy, oz = station
    dx, dy, dz = sx - ox, sy - oy, sz - oz
    lat, lon = math.radians(station_lat), math.radians(station_lon)
    sin_lat, cos_lat = math.sin(lat), math.cos(lat)
    sin_lon, cos_lon = math.sin(lon), math.cos(lon)
    east = -sin_lon * dx + cos_lon * dy
    north = -sin_lat * cos_lon * dx - sin_lat * sin_lon * dy + cos_lat * dz
    up = cos_lat * cos_lon * dx + cos_lat * sin_lon * dy + sin_lat * dz
    distance = math.sqrt(east * east + north * north + up * up)
    elevation = math.degrees(math.asin(up / distance))
    azimuth = math.degrees(math.atan2(east, north)) % 360.0
    return elevation, azimuth

# =========================================================
# FIND NEXT CONTACT
# =========================================================
def find_contact(sat, station_lat, station_lon, station):
    """Find the next time the satellite crosses above 30 degrees elevation."""
    now = datetime.now(timezone.utc)
    step = timedelta(seconds=1)
    previous_time = now
    previous_alt, _ = look_angles(sat, station_lat, station_lon, station, previous_time)
    print(f"[+] Current elevation: {previous_alt:.6f}°")
    for _ in range(7 * 24 * 60 * 60):
        current_time = previous_time + step
        current_alt, _ = look_angles(sat, station_lat, station_lon, station, current_time)
        if previous_alt <= MIN_ELEVATION and current_alt > MIN_ELEVATION:
            print("[+] Found 30° crossing:")
            print(f"    {previous_time}")
            print(f"    {current_time}")
            low, high = previous_time, current_time
            for _ in range(50):
                middle = low + (high - low) / 2
                alt, _ = look_angles(sat, station_lat, station_lon, station, middle)
                if alt > MIN_ELEVATION:
                    high = middle
                else:
                    low = middle
            return high
        previous_time, previous_alt = current_time, current_alt
    raise RuntimeError("No contact window found within 7 days")

# =========================================================
# PARSE CHALLENGE
# =========================================================
def parse_challenge(text):
    """Extract TLE and ground station coordinates."""
    tle_match = re.search(r"TLE:\s*\n[^\n]+\n(1\s.+)\n(2\s.+)", text)
    if not tle_match:
        raise RuntimeError("Failed to parse TLE")
    tle1, tle2 = tle_match.group(1).strip(), tle_match.group(2).strip()
    station_match = re.search(r"\(Lat,Long\):\s*([-+0-9.eE]+)\s*,\s*([-+0-9.eE]+)", text)
    if not station_match:
        raise RuntimeError("Failed to parse station coordinates")
    lat, lon = float(station_match.group(1)), float(station_match.group(2))
    return tle1, tle2, lat, lon

# =========================================================
# SOLVE ONE SATELLITE
# =========================================================
def solve_satellite(text, number):
    print()
    print("=" * 70)
    print(f"[*] Solving Challenge Sat {number}")
    print("=" * 70)
    tle1, tle2, lat, lon = parse_challenge(text)
    print(f"[+] Station: {lat}, {lon}")
    print("[+] TLE:")
    print(tle1)
    print(tle2)
    sat = Satrec.twoline2rv(tle1, tle2)
    station = observer_ecef(lat, lon)
    print("[*] Searching for next contact...")
    crossing = find_contact(sat, lat, lon, station)
    start = crossing.replace(microsecond=0)
    if start <= crossing:
        start += timedelta(seconds=1)
    while True:
        alt, az = look_angles(sat, lat, lon, station, start)
        if alt > MIN_ELEVATION:
            break
        start += timedelta(seconds=1)
    print()
    print(f"[+] Contact starts: {start.isoformat()}")
    values = []
    print()
    for i in range(60):
        dt = start + timedelta(seconds=i)
        alt, az = look_angles(sat, lat, lon, station, dt)
        value = f"{alt:.4f}:{az:.4f}"
        values.append(value)
        print(f"{i:02d} ALT={alt:.4f} AZ={az:.4f}")
    return " ".join(values)

# =========================================================
# EXTRACT CHALLENGE FROM SERVER DATA
# =========================================================
def has_challenge(text):
    return (re.search(r"Challenge Sat\s+\d+", text) is not None
            and "TLE:" in text and "(Lat,Long):" in text)

# =========================================================
# MAIN
# =========================================================
def main():
    print(f"[*] Connecting to {HOST}:{PORT}")
    raw_sock = socket.create_connection((HOST, PORT), timeout=30)
    raw_sock.settimeout(30)
    sock = BufferedSocket(raw_sock)
    initial = sock.recv_until(PROMPT)
    print()
    print(initial)
    challenge_number = 1
    while True:
        if not has_challenge(initial):
            print("[!] Could not find a challenge in server response.")
            print("[!] Server response:")
            print(initial)
            break
        try:
            answer = solve_satellite(initial, challenge_number)
        except Exception as e:
            print()
            print(f"[!] Failed to solve Sat {challenge_number}: {e}")
            break
        print()
        print(f"[*] Sending answer for Sat {challenge_number}...")
        try:
            raw_sock.sendall((answer + "\n").encode())
        except Exception as e:
            print(f"[!] Failed to send answer: {e}")
            break
        try:
            response = sock.recv_until(PROMPT)
        except RuntimeError as e:
            print()
            print(f"[!] {e}")
            break
        print()
        print("[SERVER RESPONSE]")
        print(response)
        print("[END SERVER RESPONSE]")
        if "Correct!" in response:
            print()
            print(f"[+] Sat {challenge_number} accepted!")
            if has_challenge(response):
                challenge_number += 1
                initial = response
                continue
            challenge_number += 1
            try:
                initial = sock.recv_until(PROMPT)
            except RuntimeError:
                print()
                print("[+] Server closed connection after successful answer.")
                break
            continue
        if ("Incorrect" in response or "Wrong" in response
                or "wrong" in response or "Failed" in response):
            print()
            print(f"[!] Sat {challenge_number} was rejected.")
            break
        if ("HTB{" in response or "flag" in response.lower()
                or "congrat" in response.lower()):
            print()
            print("[+] Possible completion:")
            print(response)
            break
        print()
        print("[!] Unexpected server response.")
        break
    try:
        raw_sock.close()
    except Exception:
        pass

if __name__ == "__main__":
    main()
```

## The Whole Solve, End to End

Zooming back out, here's the complete pipeline the script implements, from raw TLE text to a submitted flag:

```text
                    Connect to challenge server (TCP socket)
                                    │
                                    ▼
                Parse TLE + ground station coords (regex)
                                    │
                                    ▼
                     Load orbit into SGP4 (Satrec)
                                    │
                                    ▼
              Step forward second-by-second from "now"
                                    │
                                    ▼
                    Elevation crosses above 30°?
                       /                      \
                     NO                        YES
                      │                         │
                      ▼                         ▼
               Keep stepping           Binary-search the exact
                                        crossing instant
                                                 │
                                                 ▼
                                     Contact window starts (T)
                                                 │
                                                 ▼
                              Loop over T, T+1s, ..., T+59s
                                                 │
                                                 ▼
                          Compute elevation + azimuth for each
                                                 │
                                                 ▼
                        Format as "elevation:azimuth" pairs
                                                 │
                                                 ▼
                            Send all 60 pairs back to server
                                                 │
                                                 ▼
                        Repeat for satellites 2 and 3 → flag
```

The solver never has to "guess" where the satellite is — every value it produces is a deterministic calculation from three known inputs:

```text
   TLE  +  Time  +  Ground Station Coordinates
                    │
                    ▼
          Satellite Position
                    │
                    ▼
          Elevation + Azimuth
```

Run the script, and this is the output:

![](https://kur0sh1r0.gitbook.io/ctf-writeups/~gitbook/image?url=https%3A%2F%2F271954773-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYsivTjPn2jLXI0ZgVqeF%252Fuploads%252FMNmL6UpAjXD5IpJfdyVu%252FScreenshot%2520%283164%29.png%3Falt%3Dmedia%26token%3Db0f2c37f-47ba-438c-ab45-a140f89c4561&width=768&dpr=3&quality=100&sign=0f3baf05645a60868dc989ea7bd3b95d&sv=3)

It asks for **three satellites** in a row before handing over the flag.

## Conclusion

And that's it for **Antenna Pointing**!

This challenge was a genuinely different experience compared to the usual CTF fare. Instead of exploiting a web application or reverse-engineering a binary, we had to work with **satellite orbital data, coordinate systems, and orbital propagation** to figure out exactly where a satellite would appear from a given ground station.

The single most important idea in the whole challenge is that a satellite's position alone isn't enough — azimuth and elevation are fundamentally **observer-relative** measurements. Once that clicks, the rest is just a chain of coordinate transformations: orbit → Earth-fixed position → local East-North-Up vector → elevation/azimuth.

What initially looked like an intimidating astronomy problem became much easier once broken into small, well-defined steps: propagate the orbit, convert coordinate frames, subtract vectors, and take a couple of trig functions. That's also what made writing the math manually (instead of leaning on a high-level library) worthwhile — it forces you to actually understand each transformation rather than trusting a black box.

I really enjoyed this challenge because it's a great reminder that **CTFs aren't limited to traditional hacking techniques**. Sometimes solving the problem means picking up just enough of an entirely different technical field — in this case, orbital mechanics — and turning that understanding into working code.

Hack The Box's new **Satellite** category is a refreshing addition, and I'm looking forward to seeing what other challenges they come up with next.
