# frozen_string_literal: true

class CSV
  # Internal: reads within the byte budget and turns ranked evidence
  # into a CSV::SniffResult.
  #
  # @api private
  class DialectProbe
    COLUMN_PREFERENCE = Dialect::COLUMN_SEPARATORS
    QUOTE_PREFERENCE = Dialect::QUOTE_CHARACTERS
    ROW_PREFERENCE = Dialect::ROW_SEPARATORS

    def self.call(source, max_bytes)
      new(source, max_bytes).call
    end

    def initialize(source, max_bytes)
      @source = source
      @max_bytes = max_bytes
    end

    def call
      sample, bytes_read, eof, replay_io = sample_source
      raw = DialectSniffer.new(sample, eof: eof).candidates
      build_result(sample, bytes_read, eof, replay_io, raw)
    end

    private

    def sample_source
      if @source.is_a?(String)
        data = @source
        return [data.dup, data.bytesize, true, data]
      end

      sample = String.new(encoding: Encoding::BINARY)
      eof = false
      while sample.bytesize < @max_bytes
        room = @max_bytes - sample.bytesize
        # Ask for the whole remaining budget at once; IOs are free to
        # return less (a few bytes at a time is fine). We keep reading
        # until the budget is met or the source reports EOF.
        chunk = read_chunk(room)
        break if chunk.nil?
        chunk = chunk.b
        if chunk.bytesize > room
          sample << chunk.byteslice(0, room)
          eof = false
          break
        end
        sample << chunk
        if chunk.empty?
          eof = true
          break
        end
        # A short read only proves EOF when the IO agrees; otherwise
        # the IO just delivered a small chunk.
        if chunk.bytesize < room
          if @source.respond_to?(:eof?) && !@source.eof?
            next
          end
          eof = true
          break
        end
      end
      eof ||= sample.bytesize < @max_bytes
      unless eof
        eof = @source.respond_to?(:eof?) ? !!@source.eof? : false
      end

      encoding = @source.external_encoding if @source.respond_to?(:external_encoding)
      replay_io = ReplayIO.new(sample, @source, encoding: encoding)
      [sample, sample.bytesize, eof, replay_io]
    end

    def read_chunk(count)
      if @source.respond_to?(:read)
        @source.read(count)
      else
        @source.gets(nil, count)
      end
    end

    def build_result(sample, bytes_read, eof, replay_io_or_data, raw)
      entries = raw.map do |(col, quote, row), info|
        {
          col_sep: col,
          quote_char: quote,
          row_sep: row,
          info: info,
        }
      end

      reasons = []
      empty_sample = sample.b.strip.empty?
      reasons << :insufficient_evidence if empty_sample

      # Column axis is decided ignoring only mid-data hard errors; an
      # unterminated quote at the *end* of the available bytes still
      # leaves a valid (if truncated) multi-column prefix.
      structure_pool = entries.reject { |entry| entry[:info][:hard_error] }
      column = decide_column(structure_pool, eof)
      col_winner = column[:winner]
      reasons.concat(column[:reasons])

      quote = decide_quote(structure_pool, col_winner)
      row = decide_row(structure_pool, col_winner, quote[:winner], eof)
      reasons.concat(quote[:reasons])
      reasons.concat(row[:reasons])

      winner_info =
        if col_winner && quote[:winner]
          best_pair_info(entries, col_winner, quote[:winner])
        end

      truncated_quote =
        winner_info && winner_info[:unclosed_quote] && !eof
      unclosed_at_eof =
        winner_info && winner_info[:unclosed_quote] && eof

      globally_hard = (!empty_sample) && entries.all? do |entry|
        info = entry[:info]
        info[:hard_error] || (info[:unclosed_quote] && eof)
      end

      if truncated_quote
        # More bytes may close the field: this is "not enough sample",
        # not damage.
        reasons << :truncated_quoted_field
      elsif globally_hard || unclosed_at_eof
        reasons << :corrupt
      elsif winner_info && !winner_info[:consistent]
        reasons << :inconsistent_columns
      end
      reasons.uniq!

      dialects = build_dialects(entries, column, quote, row)
      evidence = {
        bytes_read: bytes_read,
        eof: eof,
        column: column.reject { |key, _| key == :reasons },
        quote: quote.reject { |key, _| key == :reasons },
        row: row.reject { |key, _| key == :reasons },
        ranked: entries.sort_by { |entry| ranking_key(entry) }
                        .map { |entry| summarize(entry) },
      }

      SniffResult.new(candidates: dialects,
                      bytes_read: bytes_read,
                      eof: eof,
                      truncated: truncated_quote,
                      reasons: reasons,
                      evidence: evidence,
                      io: replay_io_or_data.respond_to?(:read) ? replay_io_or_data : nil,
                      data: replay_io_or_data.respond_to?(:read) ? nil : replay_io_or_data)
    end

    def best_row_sep(entries, col, quote_char)
      matching = entries.select do |entry|
        entry[:col_sep] == col && entry[:quote_char] == quote_char
      end
      winner = matching.min_by do |entry|
        [-entry[:info][:scores][:row],
         ROW_PREFERENCE.index(entry[:row_sep])]
      end
      winner && winner[:row_sep]
    end

    # The highest row-score info for a col_sep/quote_char pair.
    def best_pair_info(entries, col, quote_char)
      row_sep = best_row_sep(entries, col, quote_char)
      return nil unless row_sep
      entries.find do |entry|
        entry[:col_sep] == col && entry[:quote_char] == quote_char &&
          entry[:row_sep] == row_sep
      end&.dig(:info)
    end

    # Ranked candidate dialects. The resolved winning dialect comes
    # first; each candidate carries the best record separator for its
    # own col_sep/quote_char pair (or :auto when none was observed).
    def build_dialects(entries, column, quote, row)
      grouped = {}
      entries.each do |entry|
        key = [entry[:col_sep], entry[:quote_char]]
        existing = grouped[key]
        if existing.nil? || entry[:info][:scores][:total] > existing[:info][:scores][:total]
          grouped[key] = entry.merge(candidate_row_sep: candidate_row_sep(entries, entry))
        end
      end

      winner_col = column[:winner]
      winner_quote = quote[:winner]
      winner_row = row[:winner]
      ordered = grouped.values.sort_by do |entry|
        winner_bump = (entry[:col_sep] == winner_col &&
                       entry[:quote_char] == winner_quote) ? 0 : 1
        [winner_bump,
         -entry[:info][:scores][:column],
         COLUMN_PREFERENCE.index(entry[:col_sep]),
         QUOTE_PREFERENCE.index(entry[:quote_char])]
      end

      ordered.map do |entry|
        row_sep = entry[:candidate_row_sep]
        if entry[:col_sep] == winner_col && entry[:quote_char] == winner_quote
          row_sep = winner_row || row_sep || :auto
        end
        Dialect.new(col_sep: entry[:col_sep],
                    quote_char: entry[:quote_char],
                    row_sep: row_sep,
                    evidence: summarize(entry))
      end
    end

    def candidate_row_sep(entries, entry)
      same_pair = entries.select do |candidate|
        candidate[:col_sep] == entry[:col_sep] &&
          candidate[:quote_char] == entry[:quote_char]
      end
      counts = Hash.new(0)
      same_pair.each do |candidate|
        analysis = candidate[:info][:analysis]
        counts["\r\n"] += analysis.newline_counts[DialectSniffer::CRLF]
        counts["\n"] += analysis.newline_counts[DialectSniffer::LF]
        counts["\r"] += analysis.newline_counts[DialectSniffer::CR]
      end
      observed = Dialect::ROW_SEPARATORS.select { |row_sep| counts[row_sep] > 0 }
      return :auto if observed.empty?
      observed.max_by { |row_sep| [counts[row_sep], -ROW_PREFERENCE.index(row_sep)] }
    end

    def ranking_key(entry)
      [
        -entry[:info][:scores][:total],
        COLUMN_PREFERENCE.index(entry[:col_sep]),
        QUOTE_PREFERENCE.index(entry[:quote_char]),
        ROW_PREFERENCE.index(entry[:row_sep]),
      ]
    end

    # Column axis. Ties only count as genuine ambiguity when two
    # separators each explain a confirmed multi-column shape.
    def decide_column(viable, eof)
      best = {}
      viable.each do |entry|
        col = entry[:col_sep]
        score = entry[:info][:scores][:column]
        if best[col].nil? || score > best[col][:info][:scores][:column]
          best[col] = entry
        end
      end

      if best.empty?
        return { winner: nil, leaders: [], reasons: [:insufficient_evidence] }
      end

      maximum = best.values.map { |entry| entry[:info][:scores][:column] }.max
      leaders = best.keys.select { |col| best[col][:info][:scores][:column] == maximum }
      winner = leaders.min_by { |col| COLUMN_PREFERENCE.index(col) }
      info = best[winner][:info]

      reasons = []
      ambiguous = leaders.select do |col|
        best[col][:info][:dominant_columns] > 1 &&
          best[col][:info][:structurally_confirmed]
      end
      reasons << :ambiguous_column_separator if ambiguous.size > 1

      if info[:dominant_columns] <= 1
        reasons << :insufficient_evidence
      elsif !info[:structurally_confirmed]
        reasons << (eof ? :single_record : :truncated)
      end

      { winner: winner, leaders: leaders,
        dominant_columns: info[:dominant_columns],
        score: maximum, reasons: reasons }
    end

    # Quote axis. Unobserved quoting keeps the double quote silently;
    # only a tie on *observed* quote behavior is ambiguity.
    def decide_quote(viable, winner_col)
      if winner_col.nil?
        return { winner: '"', leaders: [], observed: false, reasons: [] }
      end

      best = {}
      observed = false
      viable.each do |entry|
        next unless entry[:col_sep] == winner_col
        quote_char = entry[:quote_char]
        observed ||= entry[:info][:analysis].quoted_runs > 0
        score = entry[:info][:scores][:quote]
        if best[quote_char].nil? || score > best[quote_char][:info][:scores][:quote]
          best[quote_char] = entry
        end
      end

      maximum = best.values.map { |entry| entry[:info][:scores][:quote] }.max
      leaders = best.keys.select do |quote_char|
        best[quote_char][:info][:scores][:quote] == maximum
      end
      winner = leaders.min_by { |quote_char| QUOTE_PREFERENCE.index(quote_char) }
      reasons = []
      # Only flag ambiguity when two quote characters both show real,
      # balanced quoting evidence (a stray bare quote isn't evidence).
      quoted_leaders = leaders.count do |quote_char|
        best[quote_char][:info][:analysis].quoted_runs > 0
      end
      reasons << :ambiguous_quote_character if quoted_leaders > 1
      { winner: winner, leaders: leaders, observed: observed,
        score: maximum, reasons: reasons }
    end

    # Record separator axis for the winning col_sep/quote_char pair.
    def decide_row(viable, winner_col, winner_quote, eof)
      if winner_col.nil?
        return { winner: nil, leaders: [], observed: false, reasons: [] }
      end

      best = {}
      viable.each do |entry|
        next unless entry[:col_sep] == winner_col && entry[:quote_char] == winner_quote
        row_sep = entry[:row_sep]
        score = entry[:info][:scores][:row]
        if best[row_sep].nil? || score > best[row_sep][:info][:scores][:row]
          best[row_sep] = entry
        end
      end

      observed = best.any? do |row_sep, entry|
        entry[:info][:analysis].newline_counts[row_sep.b] > 0
      end
      unless observed
        return { winner: nil, leaders: [], observed: false, reasons: [] }
      end

      maximum = best.values.map { |entry| entry[:info][:scores][:row] }.max
      leaders = best.keys.select { |row_sep| best[row_sep][:info][:scores][:row] == maximum }
      winner = leaders.min_by { |row_sep| ROW_PREFERENCE.index(row_sep) }

      reasons = []
      reasons << :ambiguous_row_separator if leaders.size > 1

      # Mixed line endings are inherently ambiguous even when one kind
      # is numerically ahead: both really terminate records.
      winner_info = best[winner][:info]
      counts = winner_info[:analysis].newline_counts
      present = [Dialect::ROW_SEPARATORS[0],
                 Dialect::ROW_SEPARATORS[1],
                 Dialect::ROW_SEPARATORS[2]].select do |row_sep|
        counts[row_sep.b].to_i > 0
      end
      reasons << :ambiguous_row_separator if present.size > 1

      if winner_info[:ends_with_cr] && !eof &&
          counts[DialectSniffer::LF].zero? && counts[DialectSniffer::CRLF].zero?
        reasons << :truncated_cr
      end

      { winner: winner, leaders: leaders, observed: true,
        score: maximum, reasons: reasons }
    end

    def summarize(entry)
      info = entry[:info]
      analysis = info[:analysis]
      {
        scores: info[:scores],
        rows: analysis.rows,
        completed_rows: analysis.completed_rows,
        dominant_columns: info[:dominant_columns],
        quoted_runs: analysis.quoted_runs,
        newline_counts: analysis.newline_counts.each_with_object({}) do |(key, count), readable|
          readable[key.dup.force_encoding(Encoding::UTF_8)] = count
        end,
        consistent: info[:consistent],
        structurally_confirmed: info[:structurally_confirmed],
        unclosed_quote: info[:unclosed_quote],
        hard_error: info[:hard_error],
      }
    end
  end
end
