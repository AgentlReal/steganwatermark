"""
Steganalysis and Security Evaluation Module.

Implements Chi-Square (χ²) Steganalysis on Pairs of Values (PoV)
to quantitatively test whether hidden data can be detected statistically.
"""

from typing import Dict, Tuple
import numpy as np
from scipy.stats import chi2


def chi_square_steganalysis(image: np.ndarray, num_blocks: int = 16) -> Dict[str, float]:
    """
    Performs Chi-Square Steganalysis based on Pairs of Values (PoV).
    
    Pairs evaluated: (2k, 2k+1) for k in [0, 127].
    Expected frequency: e_k = (count(2k) + count(2k+1)) / 2
    Chi2 statistic: sum((count(2k) - e_k)^2 / e_k)
    
    Returns:
        Dictionary containing:
        - chi2_stat: Summed Chi-Square statistic.
        - p_value: Probability of null hypothesis (p < 0.05 usually flags detected tampering).
        - detection_confidence: Estimated probability of hidden data presence (0.0 to 1.0).
        - dof: Degrees of freedom.
    """
    if image.ndim == 3:
        # Analyze luminance or blue channel
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
        # p-value: probability of observing such difference under equalized LSB hypothesis
        p_val = 1.0 - chi2.cdf(chi2_val, dof)
        # Confidence that embedding is present: 1 - p_val
        confidence = float(np.clip(1.0 - p_val, 0.0, 1.0))
    else:
        p_val = 1.0
        confidence = 0.0

    return {
        "chi2_stat": float(chi2_val),
        "dof": int(dof),
        "p_value": float(p_val),
        "detection_confidence": confidence,
        "is_detected": bool(confidence > 0.95),
    }

