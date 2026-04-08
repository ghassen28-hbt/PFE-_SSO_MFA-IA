import base64
import os
from threading import Lock
from typing import Tuple

import cv2
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from storage import load_profile, save_profile


FACE_MODEL_NAME = os.getenv("FACE_MODEL_NAME", "buffalo_l")
FACE_SIMILARITY_THRESHOLD = float(os.getenv("FACE_SIMILARITY_THRESHOLD", "0.45"))

MIN_FACE_RATIO = float(os.getenv("MIN_FACE_RATIO", "0.12"))
MIN_BLUR_SCORE = float(os.getenv("MIN_BLUR_SCORE", "40.0"))
MIN_BRIGHTNESS = float(os.getenv("MIN_BRIGHTNESS", "25.0"))
MAX_BRIGHTNESS = float(os.getenv("MAX_BRIGHTNESS", "235.0"))
MIN_FACE_DETECTION_CONFIDENCE = float(os.getenv("MIN_FACE_DETECTION_CONFIDENCE", "0.70"))

FRONT_YAW_MAX = float(os.getenv("FRONT_YAW_MAX", "0.12"))
CHALLENGE_YAW_MIN = float(os.getenv("CHALLENGE_YAW_MIN", "0.10"))
MIN_YAW_DELTA = float(os.getenv("MIN_YAW_DELTA", "0.08"))
MIN_CROSS_CAPTURE_SIM = float(os.getenv("MIN_CROSS_CAPTURE_SIM", "0.45"))
ENROLL_FRONT_YAW_MAX = float(os.getenv("ENROLL_FRONT_YAW_MAX", str(FRONT_YAW_MAX)))
ENROLL_FRONT_ROLL_MAX = float(os.getenv("ENROLL_FRONT_ROLL_MAX", "0.08"))
MAX_ROLL_DELTA = float(os.getenv("MAX_ROLL_DELTA", "0.10"))
MAX_FACE_CENTER_SHIFT = float(os.getenv("MAX_FACE_CENTER_SHIFT", "0.12"))
MAX_FACE_SCALE_DELTA = float(os.getenv("MAX_FACE_SCALE_DELTA", "0.25"))

app = FastAPI(title="Biometric Service", version="1.2.0")


class EnrollRequest(BaseModel):
    user_id: str = Field(..., min_length=1)
    username: str = Field(default="")
    image_base64: str = Field(..., min_length=30)


class VerifyRequest(BaseModel):
    user_id: str = Field(..., min_length=1)
    username: str = Field(default="")
    image_base64: str = Field(..., min_length=30)
    challenge_image_base64: str | None = Field(default=None)
    challenge_type: str = Field(default="turn_left")
    enforce_liveness: bool = Field(default=True)


_face_app = None
_face_lock = Lock()


def get_face_app():
    global _face_app

    if _face_app is None:
        with _face_lock:
            if _face_app is None:
                try:
                    from insightface.app import FaceAnalysis
                except Exception as exc:
                    raise RuntimeError(
                        "InsightFace n'est pas installé correctement. Vérifie requirements.txt."
                    ) from exc

                print(f"[biometric-service] loading model: {FACE_MODEL_NAME}")

                _face_app = FaceAnalysis(
                    name=FACE_MODEL_NAME,
                    providers=["CPUExecutionProvider"],
                )
                _face_app.prepare(ctx_id=0, det_size=(640, 640))

                print(f"[biometric-service] model ready: {FACE_MODEL_NAME}")

    return _face_app


@app.on_event("startup")
def startup_load_model():
    get_face_app()


def decode_image(image_base64: str) -> np.ndarray:
    try:
        payload = image_base64.split(",", 1)[1] if "," in image_base64 else image_base64
        raw = base64.b64decode(payload)
        arr = np.frombuffer(raw, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Image invalide: {exc}") from exc

    if img is None:
        raise HTTPException(status_code=400, detail="Impossible de décoder l'image.")

    return img


def ensure_single_face(faces):
    if not faces:
        raise HTTPException(status_code=400, detail="Aucun visage détecté.")
    if len(faces) > 1:
        raise HTTPException(
            status_code=400,
            detail="Plusieurs visages détectés. Une seule personne doit apparaître devant la caméra.",
        )


def pick_primary_face(faces):
    ensure_single_face(faces)

    def area(face):
        x1, y1, x2, y2 = face.bbox.astype(int).tolist()
        return max(0, x2 - x1) * max(0, y2 - y1)

    return sorted(faces, key=area, reverse=True)[0]


def face_geometry(img: np.ndarray, face) -> dict:
    h, w = img.shape[:2]
    x1, y1, x2, y2 = face.bbox.astype(int).tolist()

    x1 = max(0, x1)
    y1 = max(0, y1)
    x2 = min(w, x2)
    y2 = min(h, y2)

    face_w = max(1, x2 - x1)
    face_h = max(1, y2 - y1)
    center_x = ((x1 + x2) / 2.0) / max(w, 1)
    center_y = ((y1 + y2) / 2.0) / max(h, 1)
    area_ratio = (face_w * face_h) / max(float(w * h), 1.0)

    return {
        "bbox_center_x_ratio": round(float(center_x), 4),
        "bbox_center_y_ratio": round(float(center_y), 4),
        "bbox_area_ratio": round(float(area_ratio), 4),
    }


def estimate_pose(face) -> dict:
    yaw_proxy = 0.0
    roll_proxy = 0.0

    kps = getattr(face, "kps", None)
    if kps is not None:
        pts = np.asarray(kps, dtype=np.float32)
        if pts.shape[0] >= 3:
            left_eye = pts[0]
            right_eye = pts[1]
            nose = pts[2]

            eye_mid_x = float((left_eye[0] + right_eye[0]) / 2.0)
            eye_distance = float(max(1.0, abs(right_eye[0] - left_eye[0])))

            yaw_proxy = float((nose[0] - eye_mid_x) / eye_distance)
            roll_proxy = float((right_eye[1] - left_eye[1]) / eye_distance)

    return {
        "yaw_proxy": round(yaw_proxy, 4),
        "roll_proxy": round(roll_proxy, 4),
    }


def image_quality_checks(img: np.ndarray, face) -> dict:
    h, w = img.shape[:2]
    x1, y1, x2, y2 = face.bbox.astype(int).tolist()

    x1 = max(0, x1)
    y1 = max(0, y1)
    x2 = min(w, x2)
    y2 = min(h, y2)

    face_w = max(1, x2 - x1)
    face_h = max(1, y2 - y1)
    face_ratio = max(face_w / max(w, 1), face_h / max(h, 1))

    face_crop = img[y1:y2, x1:x2]
    if face_crop.size == 0:
        raise HTTPException(status_code=400, detail="Zone de visage invalide.")

    gray = cv2.cvtColor(face_crop, cv2.COLOR_BGR2GRAY)
    blur_score = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    brightness = float(gray.mean())

    checks = {
        "face_ratio": round(face_ratio, 4),
        "blur_score": round(blur_score, 2),
        "brightness": round(brightness, 2),
    }

    if face_ratio < MIN_FACE_RATIO:
        raise HTTPException(
            status_code=400,
            detail=f"Visage trop éloigné. Ratio détecté={checks['face_ratio']}, minimum={MIN_FACE_RATIO}.",
        )

    if blur_score < MIN_BLUR_SCORE:
        raise HTTPException(
            status_code=400,
            detail=f"Image trop floue. Blur score={checks['blur_score']}, minimum={MIN_BLUR_SCORE}.",
        )

    if brightness < MIN_BRIGHTNESS or brightness > MAX_BRIGHTNESS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Luminosité non conforme. Brightness={checks['brightness']}, "
                f"intervalle attendu=[{MIN_BRIGHTNESS}, {MAX_BRIGHTNESS}]."
            ),
        )

    return checks


def validate_face_detection(face_confidence: float):
    if face_confidence < MIN_FACE_DETECTION_CONFIDENCE:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Détection faciale trop faible. Confidence={round(face_confidence, 4)}, "
                f"minimum={MIN_FACE_DETECTION_CONFIDENCE}."
            ),
        )


def validate_enrollment_pose(meta: dict):
    yaw = abs(float(meta.get("yaw_proxy", 0.0)))
    roll = abs(float(meta.get("roll_proxy", 0.0)))

    if yaw > ENROLL_FRONT_YAW_MAX:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Pour l'enrôlement, le visage doit rester frontal. "
                f"Yaw détecté={round(yaw, 4)}, maximum={ENROLL_FRONT_YAW_MAX}."
            ),
        )

    if roll > ENROLL_FRONT_ROLL_MAX:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Pour l'enrôlement, évite d'incliner la tête ou l'écran. "
                f"Roll détecté={round(roll, 4)}, maximum={ENROLL_FRONT_ROLL_MAX}."
            ),
        )


def extract_face_data(img: np.ndarray) -> Tuple[np.ndarray, dict]:
    face_app = get_face_app()
    faces = face_app.get(img)

    face = pick_primary_face(faces)
    quality = image_quality_checks(img, face)
    pose = estimate_pose(face)
    geometry = face_geometry(img, face)

    embedding = getattr(face, "embedding", None)
    if embedding is None:
        raise HTTPException(status_code=500, detail="Embedding facial indisponible.")

    confidence = float(getattr(face, "det_score", 0.0) or 0.0)
    validate_face_detection(confidence)

    return np.asarray(embedding, dtype=np.float32), {
        **quality,
        **pose,
        **geometry,
        "detected_faces": len(faces),
        "face_confidence": round(confidence, 4),
    }


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)


def evaluate_liveness(primary_meta: dict, challenge_meta: dict, challenge_type: str) -> dict:
    challenge_type = (challenge_type or "").strip().lower()
    if challenge_type not in {"turn_right", "turn_left"}:
        raise HTTPException(status_code=400, detail="Challenge de liveness non supporté.")

    yaw_primary = float(primary_meta.get("yaw_proxy", 0.0))
    yaw_challenge = float(challenge_meta.get("yaw_proxy", 0.0))
    roll_primary = float(primary_meta.get("roll_proxy", 0.0))
    roll_challenge = float(challenge_meta.get("roll_proxy", 0.0))
    motion_delta = round(yaw_challenge - yaw_primary, 4)
    roll_delta = round(abs(roll_challenge - roll_primary), 4)
    center_shift = round(
        float(
            np.hypot(
                float(challenge_meta.get("bbox_center_x_ratio", 0.0))
                - float(primary_meta.get("bbox_center_x_ratio", 0.0)),
                float(challenge_meta.get("bbox_center_y_ratio", 0.0))
                - float(primary_meta.get("bbox_center_y_ratio", 0.0)),
            )
        ),
        4,
    )
    primary_area = max(float(primary_meta.get("bbox_area_ratio", 0.0)), 1e-6)
    challenge_area = float(challenge_meta.get("bbox_area_ratio", 0.0))
    scale_delta = round(abs(challenge_area - primary_area) / primary_area, 4)

    primary_frontal_ok = abs(yaw_primary) <= FRONT_YAW_MAX

    if challenge_type == "turn_right":
        challenge_ok = yaw_challenge >= CHALLENGE_YAW_MIN and motion_delta >= MIN_YAW_DELTA
    else:
        challenge_ok = yaw_challenge <= -CHALLENGE_YAW_MIN and motion_delta <= -MIN_YAW_DELTA

    framing_ok = center_shift <= MAX_FACE_CENTER_SHIFT and scale_delta <= MAX_FACE_SCALE_DELTA
    roll_ok = roll_delta <= MAX_ROLL_DELTA
    liveness_passed = primary_frontal_ok and challenge_ok and framing_ok and roll_ok

    if not primary_frontal_ok:
        reason = "primary_not_frontal"
    elif not challenge_ok:
        reason = f"{challenge_type}_not_detected"
    elif not roll_ok:
        reason = "roll_delta_too_large"
    elif not framing_ok and center_shift > MAX_FACE_CENTER_SHIFT:
        reason = "framing_shift_too_large"
    elif not framing_ok:
        reason = "face_scale_changed_too_much"
    else:
        reason = "active_liveness_passed"

    return {
        "liveness_passed": liveness_passed,
        "liveness_reason": reason,
        "challenge_type": challenge_type,
        "yaw_primary": round(yaw_primary, 4),
        "yaw_challenge": round(yaw_challenge, 4),
        "roll_primary": round(roll_primary, 4),
        "roll_challenge": round(roll_challenge, 4),
        "motion_delta": motion_delta,
        "roll_delta": roll_delta,
        "center_shift": center_shift,
        "scale_delta": scale_delta,
        "primary_frontal_ok": primary_frontal_ok,
        "roll_ok": roll_ok,
        "framing_ok": framing_ok,
    }


@app.get("/")
def root():
    return {
        "service": "biometric-service",
        "status": "ok",
        "model": FACE_MODEL_NAME,
        "threshold": FACE_SIMILARITY_THRESHOLD,
        "model_ready": _face_app is not None,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model": FACE_MODEL_NAME,
        "threshold": FACE_SIMILARITY_THRESHOLD,
        "model_ready": _face_app is not None,
    }


@app.get("/profiles/{user_id}")
def get_profile(user_id: str):
    profile = load_profile(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profil biométrique introuvable.")

    return {
        "enrolled": True,
        "user_id": profile["user_id"],
        "username": profile.get("username", ""),
        "enrolled_at": profile.get("enrolled_at"),
        "quality_score": profile.get("quality_score"),
        "face_confidence": profile.get("face_confidence"),
        "model": profile.get("model"),
    }


@app.post("/enroll")
def enroll(payload: EnrollRequest):
    img = decode_image(payload.image_base64)
    embedding, meta = extract_face_data(img)
    validate_enrollment_pose(meta)

    quality_score = round(
        min(
            1.0,
            0.45 * min(1.0, meta["blur_score"] / max(MIN_BLUR_SCORE, 1.0))
            + 0.35 * meta["face_confidence"]
            + 0.20 * min(1.0, meta["face_ratio"] / max(MIN_FACE_RATIO, 0.01)),
        ),
        4,
    )

    record = save_profile(
        user_id=payload.user_id,
        username=payload.username,
        embedding=embedding.tolist(),
        model=FACE_MODEL_NAME,
        quality_score=quality_score,
        face_confidence=meta["face_confidence"],
        extra_meta=meta,
    )

    return {
        "status": "ok",
        "message": "Profil biométrique enrôlé avec succès.",
        "user_id": record["user_id"],
        "username": record.get("username", ""),
        "enrolled_at": record["enrolled_at"],
        "quality_score": record["quality_score"],
        "face_confidence": record["face_confidence"],
        "model": record["model"],
        "quality_checks": {
            "detected_faces": meta["detected_faces"],
            "face_ratio": meta["face_ratio"],
            "blur_score": meta["blur_score"],
            "brightness": meta["brightness"],
            "yaw_proxy": meta["yaw_proxy"],
            "roll_proxy": meta["roll_proxy"],
            "bbox_center_x_ratio": meta["bbox_center_x_ratio"],
            "bbox_center_y_ratio": meta["bbox_center_y_ratio"],
            "bbox_area_ratio": meta["bbox_area_ratio"],
        },
    }


@app.post("/verify")
def verify(payload: VerifyRequest):
    profile = load_profile(payload.user_id)
    if not profile:
        raise HTTPException(
            status_code=404,
            detail="Aucun profil biométrique enrôlé pour cet utilisateur.",
        )

    reference = np.asarray(profile["embedding"], dtype=np.float32)

    primary_img = decode_image(payload.image_base64)
    primary_embedding, primary_meta = extract_face_data(primary_img)
    similarity_primary = round(cosine_similarity(reference, primary_embedding), 4)

    similarity_challenge = None
    cross_capture_similarity = None
    challenge_meta = None
    liveness = {
        "liveness_passed": True,
        "liveness_reason": "not_required",
        "challenge_type": payload.challenge_type,
        "yaw_primary": primary_meta["yaw_proxy"],
        "yaw_challenge": None,
        "roll_primary": primary_meta["roll_proxy"],
        "roll_challenge": None,
        "motion_delta": 0.0,
        "roll_delta": 0.0,
        "center_shift": 0.0,
        "scale_delta": 0.0,
        "primary_frontal_ok": True,
        "roll_ok": True,
        "framing_ok": True,
    }

    if payload.enforce_liveness:
        if not payload.challenge_image_base64:
            raise HTTPException(
                status_code=400,
                detail="Une deuxième capture est requise pour le liveness actif.",
            )

        challenge_img = decode_image(payload.challenge_image_base64)
        challenge_embedding, challenge_meta = extract_face_data(challenge_img)

        similarity_challenge = round(cosine_similarity(reference, challenge_embedding), 4)
        cross_capture_similarity = round(
            cosine_similarity(primary_embedding, challenge_embedding), 4
        )

        liveness = evaluate_liveness(
            primary_meta,
            challenge_meta,
            payload.challenge_type,
        )

        if cross_capture_similarity < MIN_CROSS_CAPTURE_SIM:
            liveness["liveness_passed"] = False
            liveness["liveness_reason"] = "cross_capture_similarity_too_low"

    verified = (
        similarity_primary >= FACE_SIMILARITY_THRESHOLD
        and (
            similarity_challenge is None
            or similarity_challenge >= FACE_SIMILARITY_THRESHOLD
        )
        and liveness["liveness_passed"] is True
    )

    reason = (
        "face_verified_with_liveness"
        if verified
        else (
            liveness["liveness_reason"]
            if not liveness["liveness_passed"]
            else "face_mismatch"
        )
    )

    return {
        "status": "ok",
        "verified": verified,
        "reason": reason,
        "user_id": payload.user_id,
        "username": payload.username,
        "model": profile.get("model", FACE_MODEL_NAME),
        "threshold": FACE_SIMILARITY_THRESHOLD,
        "similarity_primary": similarity_primary,
        "similarity_challenge": similarity_challenge,
        "cross_capture_similarity": cross_capture_similarity,
        "liveness_passed": liveness["liveness_passed"],
        "liveness_reason": liveness["liveness_reason"],
        "challenge_type": liveness["challenge_type"],
        "yaw_primary": liveness["yaw_primary"],
        "yaw_challenge": liveness["yaw_challenge"],
        "roll_primary": liveness["roll_primary"],
        "roll_challenge": liveness["roll_challenge"],
        "motion_delta": liveness["motion_delta"],
        "roll_delta": liveness["roll_delta"],
        "center_shift": liveness["center_shift"],
        "scale_delta": liveness["scale_delta"],
        "primary_frontal_ok": liveness["primary_frontal_ok"],
        "roll_ok": liveness["roll_ok"],
        "framing_ok": liveness["framing_ok"],
        "quality_checks_primary": {
            "detected_faces": primary_meta["detected_faces"],
            "face_ratio": primary_meta["face_ratio"],
            "blur_score": primary_meta["blur_score"],
            "brightness": primary_meta["brightness"],
            "yaw_proxy": primary_meta["yaw_proxy"],
            "roll_proxy": primary_meta["roll_proxy"],
            "bbox_center_x_ratio": primary_meta["bbox_center_x_ratio"],
            "bbox_center_y_ratio": primary_meta["bbox_center_y_ratio"],
            "bbox_area_ratio": primary_meta["bbox_area_ratio"],
        },
        "quality_checks_challenge": None if challenge_meta is None else {
            "detected_faces": challenge_meta["detected_faces"],
            "face_ratio": challenge_meta["face_ratio"],
            "blur_score": challenge_meta["blur_score"],
            "brightness": challenge_meta["brightness"],
            "yaw_proxy": challenge_meta["yaw_proxy"],
            "roll_proxy": challenge_meta["roll_proxy"],
            "bbox_center_x_ratio": challenge_meta["bbox_center_x_ratio"],
            "bbox_center_y_ratio": challenge_meta["bbox_center_y_ratio"],
            "bbox_area_ratio": challenge_meta["bbox_area_ratio"],
        },
        "face_confidence_primary": primary_meta["face_confidence"],
        "face_confidence_challenge": None if challenge_meta is None else challenge_meta["face_confidence"],
        "enrolled_at": profile.get("enrolled_at"),
    }
