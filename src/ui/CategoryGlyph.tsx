import {
  BadgeCheck,
  Car,
  CreditCard,
  Database,
  FileText,
  HeartPulse,
  IdCard,
  Key,
  KeyRound,
  KeySquare,
  Landmark,
  LockKeyhole,
  NotebookPen,
  Router,
  Server,
  Ticket,
  UserRound,
  Wallet,
  type LucideIcon,
} from "lucide-react";
import { META_BY_ID } from "../lib/catalog";

const GLYPHS: Record<string, LucideIcon> = {
  KeyRound,
  LockKeyhole,
  CreditCard,
  UserRound,
  NotebookPen,
  FileText,
  KeySquare,
  Server,
  Database,
  Landmark,
  Wallet,
  Car,
  IdCard,
  Ticket,
  HeartPulse,
  BadgeCheck,
  Key,
  Router,
};

/**
 * Category glyph for an item. Every category in the core has a distinct,
 * real line icon at the same optical weight (1.5px on a 24px grid).
 */
export function CategoryGlyph({
  category,
  size = 16,
  className,
}: {
  category: string;
  size?: number;
  className?: string;
}) {
  const meta = META_BY_ID[category];
  const Icon = (meta && GLYPHS[meta.glyph]) || KeyRound;
  return (
    <Icon
      size={size}
      strokeWidth={1.5}
      aria-hidden
      className={className}
      focusable={false}
    />
  );
}
