package in.akuj.fingerprint;

import java.util.ArrayList;
import java.util.List;

/**
 * Lays out a shell command for reading on the phone. Display only: the signed command, and what the
 * computer runs, are never changed, and the rows always concatenate back to the exact original text.
 *
 * <p>Every real newline starts a numbered row. Within a line, a quote-aware scan adds a display
 * break after a top-level {@code &&}, {@code ||}, {@code ;} or {@code |}; such continuation rows
 * have no number and are shown with a marker, so they cannot be mistaken for real lines. Text in
 * '…', "…", `…` and $(…) is never split. If quoting does not balance, {@link #rows} returns null and
 * the caller shows the exact text.
 */
final class CommandFormatter {
    static final String CONTINUATION = "↩ ";
    static final String TAB_FORMATTED = "    ";
    static final String TAB_EXACT = "⇥   ";

    static final class Row {
        /** Physical line number (1-based), or 0 for a display continuation of the line above. */
        final int number;
        /** The original characters of this row (no newline). */
        final String text;
        Row(int number, String text) { this.number = number; this.text = text; }
    }

    private CommandFormatter() { }

    static List<Row> rows(String command) {
        List<Row> rows = new ArrayList<>();
        StringBuilder stack = new StringBuilder(); // open contexts: ' " ` )
        int line = 1, start = 0, n = command.length();
        boolean continuation = false;
        for (int i = 0; i < n; i++) {
            char c = command.charAt(i);
            char top = stack.length() == 0 ? 0 : stack.charAt(stack.length() - 1);
            if (c == '\n') {
                rows.add(new Row(continuation ? 0 : line, command.substring(start, i)));
                line++;
                start = i + 1;
                continuation = false;
                continue;
            }
            if (top == '\'') {
                if (c == '\'') stack.setLength(stack.length() - 1);
                continue;
            }
            if (c == '\\') {
                if (i + 1 < n && command.charAt(i + 1) != '\n') i++; // escaped character (a newline still ends the row)
                continue;
            }
            if (top == '"') {
                if (c == '"') stack.setLength(stack.length() - 1);
                else if (c == '`') stack.append('`');
                else if (c == '$' && i + 1 < n && command.charAt(i + 1) == '(') { stack.append(')'); i++; }
                continue;
            }
            if (top == '`' && c == '`') { stack.setLength(stack.length() - 1); continue; }
            if (c == '\'' && top != '`') { stack.append('\''); continue; }
            if (c == '"') { stack.append('"'); continue; }
            if (c == '`') { stack.append('`'); continue; }
            if (c == '$' && i + 1 < n && command.charAt(i + 1) == '(') { stack.append(')'); i++; continue; }
            if (top == ')') {
                if (c == '(') stack.append(')');
                else if (c == ')') stack.setLength(stack.length() - 1);
                continue;
            }
            if (top != 0) continue;
            int end = separatorEnd(command, i);
            if (end < 0) continue;
            while (end < n && (command.charAt(end) == ' ' || command.charAt(end) == '\t')) end++;
            if (end < n && command.charAt(end) != '\n') {
                rows.add(new Row(continuation ? 0 : line, command.substring(start, end)));
                start = end;
                continuation = true;
            }
            i = end - 1;
        }
        if (stack.length() != 0) return null; // unbalanced quoting: show the exact text instead
        rows.add(new Row(continuation ? 0 : line, command.substring(start)));
        return rows;
    }

    /** End index (exclusive) of a top-level separator starting at i, or -1. */
    private static int separatorEnd(String text, int i) {
        char c = text.charAt(i);
        char next = i + 1 < text.length() ? text.charAt(i + 1) : 0;
        if (c == '&') return next == '&' ? i + 2 : -1; // a single & (background) is not split
        if (c == ';') return next == ';' ? i + 2 : i + 1;
        if (c == '|') {
            if (i > 0 && text.charAt(i - 1) == '>') return -1; // >| is a redirection
            return next == '|' || next == '&' ? i + 2 : i + 1;
        }
        return -1;
    }

    /** Joins rows back into the original command (for tests and as a safety check). */
    static String join(List<Row> rows) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < rows.size(); i++) {
            if (i > 0 && rows.get(i).number != 0) out.append('\n');
            out.append(rows.get(i).text);
        }
        return out.toString();
    }

    static String formattedTabs(String text) { return text.replace("\t", TAB_FORMATTED); }

    static String exactTabs(String text) { return text.replace("\t", TAB_EXACT); }
}
