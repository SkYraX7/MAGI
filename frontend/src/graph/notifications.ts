// OS-level toast notifications via the Web Notifications API.
//
// This is MAGI's alerting surface (the chosen alternative to a Slack/webhook backend):
// when a `threat_flag` arrives over the WebSocket, the browser raises a real OS toast
// (Windows Action Center / macOS Notification Center), even with the tab backgrounded.

let permission: NotificationPermission = "default";

/** Ask once for notification permission (call after a user gesture, e.g. login). */
export async function requestNotificationPermission(): Promise<void> {
  if (!("Notification" in window)) return;
  if (Notification.permission === "default") {
    permission = await Notification.requestPermission();
  } else {
    permission = Notification.permission;
  }
}

export interface ThreatFlag {
  node_id: string;
  campaign: string;
  confidence: number;
}

/** Raise an OS toast for a confirmed threat. No-op without permission/support. */
export function showThreatToast(flag: ThreatFlag): void {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  const pct = Math.round(flag.confidence * 100);
  new Notification("⚠️ MAGI — threat detected", {
    body: `${flag.campaign}\n${flag.node_id} · confidence ${pct}%`,
    tag: `magi-${flag.node_id}`, // collapse repeats for the same IP
    requireInteraction: flag.confidence >= 0.9,
  });
}

export function notificationPermission(): NotificationPermission {
  return "Notification" in window ? Notification.permission : permission;
}
