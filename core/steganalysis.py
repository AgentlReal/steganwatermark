"""
Steganalysis and Security Evaluation Module.

Implements Chi-Square (χ²) Steganalysis on Pairs of Values (PoV) (Westfeld & Pfitzmann).
In Westfeld's methodology:
- Null Hypothesis H0: The distribution of values within each pair (2k, 2k+1) is equalized
  (as produced by naive LSB replacement steganography).
- If H0 holds (equalized pairs), chi2 is small and p_value is high (p -> 1.0),
  indicating high probability of LSB replacement steganography.
- In clean natural images and under LSB Matching (±1), natural histogram asymmetries
  are preserved, so chi2 is large and p_value -> 0.0 (H0 rejected: not equalized).
"""

from typing import Dict, Tuple
import numpy as np
from scipy.stats import chi2


def chi_square_steganalysis(image: np.ndarray) -> Dict[str, float]:
    """
    Performs Chi-Square Steganalysis based on Pairs of Values (PoV).
    
    Pairs evaluated: (2k, 2k+1) for k in [0, 127].
    Expected frequency under LSB equalization: e_k = (count(2k) + count(2k+1)) / 2
    Chi2 statistic: sum((count(2k) - e_k)^2 / e_k)
    
    Returns:
        Dictionary containing:
        - chi2_stat: Summed Chi-Square statistic.
        - p_value: Probability of equalized pair hypothesis (p > 0.95 indicates naive LSB replacement).
        - detection_confidence: Estimated probability of naive LSB equalization (0.0 to 1.0).
        - is_detected: True if equalized pairs are detected (p_value > 0.95).
        - dof: Degrees of freedom.
    """
    if image.ndim == 3:
        # Evaluate green/luminance channel
        gray = (0.299 * image[:, :, 0] + 0.587 * image[:, :, 1] + 0.114 * image[:, :, 2]).astype(np.uint8)
    else:
        gray = image.astype(np.uint8)

    hist, _ = np.histogram(gray, bins=256, range=(0, 256))

    chi2_val = 0.0
    dof = 0

    for k in range(128):
        c_even = hist[2 * k]
        c_odd = hist[2 * k + 1]
        total = c_even + c_odd

        if total > 10:  # Only evaluate pairs with sufficient statistical support
            expected = total / 2.0
            term = ((c_even - expected) ** 2) / expected + ((c_odd - expected) ** 2) / expected
            chi2_val += term
            dof += 1

    if dof > 0:
        # p_val is the probability that the observed asymmetry occurred under H0 (equalized pairs)
        # High p_val (near 1.0) means pairs are unnaturally equalized -> LSB replacement detected
        # Low p_val (near 0.0) means pairs are naturally asymmetric -> no LSB replacement
        p_val = float(1.0 - chi2.cdf(chi2_val, dof))
        detection_confidence = float(np.clip(p_val, 0.0, 1.0))
    else:
        p_val = 0.0
        detection_confidence = 0.0

    return {
        "chi2_stat": float(chi2_val),
        "dof": int(dof),
        "p_value": float(p_val),
        "detection_confidence": detection_confidence,
        "is_detected": bool(detection_confidence > 0.90),
    }
