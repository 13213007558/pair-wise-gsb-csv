# frozen_string_literal: true

class CSV
  # Internal: probes a sample and ranks dialect candidates.
  #
  # The sniffer never counts bare characters: every candidate dialect
  # is run through a quote-aware tokenizer, so separators or newlines
  # inside quoted fields are never mistaken for structure.
  #
  # @api private
  class DialectSniffer
    # Score given to each consistently explained column occurrence.
    STRUCTURAL_WEIGHT = 10
    # Reward per balanced quoted run.
    QUOTED_RUN_SCORE = 4
    # Penalty per foreign separator seen outside quoted fields.
    FOREIGN_SEP_PENALTY = 3
    # Penalty per illegal quote (e.g. inside an unquoted field).
    ILLEGAL_QUOTE_PENALTY = 25
    # Penalty per record whose width disagrees with the modal width.
    WIDTH_INCONSISTENCY_PENALTY = 30
    # Reward per structural record separator.
    ROW_SEP_WEIGHT = 5

    CRLF = "\r\n".b.freeze
    LF = "\n".b.freeze
    CR = "\r".b.freeze

    Analysis = Struct.new(:rows, :completed_rows, :quoted_runs,
                          :foreign_separators, :newline_counts,
                          :unclosed_quote, :hard_error,
                          :ends_with_cr, :ends_on_record_boundary,
                          :foreign_quotes)

    # One quote-aware tokenizing pass for a col_sep/quote_byte pair.
    # All three line-ending kinds are recorded independently so the
    # same analysis can later be scored for every row separator.
    def self.analyze(sample, col_sep, quote_byte, other_separators,
                     other_quote_byte = nil)
      rows = []
      quoted_runs = 0
      foreign = Hash.new(0)
      foreign_quotes = 0
      newline_counts = {CRLF => 0, LF => 0, CR => 0}
      hard_error = false
      ends_with_cr = false
      ended_on_boundary = false

      in_quotes = false
      field_has_content = false
      closed_quote = false
      saw_separator = false
      row_has_content = false
      columns = 1
      i = 0
      bytesize = sample.bytesize

      finish_record = lambda do
        rows << ((row_has_content or saw_separator) ? columns : 0)
        columns = 1
        saw_separator = false
        row_has_content = false
        field_has_content = false
        closed_quote = false
      end

      while i < bytesize
        byte = sample.getbyte(i)

        if in_quotes
          if byte == quote_byte
            if sample.getbyte(i + 1) == quote_byte
              i += 2 # escaped quote
            else
              in_quotes = false
              closed_quote = true
              i += 1
            end
          else
            # Everything inside quotes (newlines/separators) is data.
            i += 1
          end
          next
        end

        # Record separators are legal right after a closed quote.
        if byte == 0x0d and sample.getbyte(i + 1) == 0x0a
          newline_counts[CRLF] += 1
          finish_record.call
          ended_on_boundary = true
          i += 2
          next
        elsif byte == 0x0a
          newline_counts[LF] += 1
          finish_record.call
          ended_on_boundary = true
          i += 1
          next
        elsif byte == 0x0d
          newline_counts[CR] += 1
          ends_with_cr = (i + 1 == bytesize)
          finish_record.call
          ended_on_boundary = true
          i += 1
          next
        end
        ended_on_boundary = false

        if byte == quote_byte
          if !field_has_content
            # Opening quote of a field.
            in_quotes = true
            field_has_content = true
            quoted_runs += 1
            row_has_content = true
            i += 1
            next
          end
          # Otherwise illegal (after unquoted content or a closed field).
          hard_error = true
          closed_quote = false
          i += 1
          next
        end

        if other_quote_byte && byte == other_quote_byte
          foreign_quotes += 1
        end

        # The column separator is legal right after a closed quote.
        if matched?(sample, i, col_sep)
          columns += 1
          saw_separator = true
          row_has_content = true
          field_has_content = false
          closed_quote = false
          i += col_sep.bytesize
          next
        end

        # Any other content byte after a closed quoted field is
        # illegal ("Any value after quoted field isn't allowed").
        hard_error = true if closed_quote

        other_separators.each do |other|
          foreign[other] += 1 if matched?(sample, i, other)
        end

        field_has_content = true
        row_has_content = true
        i += 1
      end

      unclosed_quote = in_quotes
      if in_quotes
      else
        rows << ((row_has_content or saw_separator) ? columns : 0)
      end

      analysis = Analysis.new(rows,
                   rows.count { |width| width > 0 },
                   quoted_runs,
                   foreign,
                   newline_counts,
                   unclosed_quote,
                   hard_error,
                   ends_with_cr,
                   ended_on_boundary,
                   foreign_quotes)
      analysis
    end

    def self.matched?(sample, index, token)
      token.bytesize.times do |offset|
        return false unless sample.getbyte(index + offset) == token.getbyte(offset)
      end
      true
    end
    private_class_method :matched?

    def initialize(sample, eof:)
      @sample = sample.b
      @eof = eof
    end

    # Returns a Hash keyed by [col_sep, quote_char, row_sep] => evidence.
    def candidates
      results = {}
      Dialect::COLUMN_SEPARATORS.each do |col_sep|
        others = Dialect::COLUMN_SEPARATORS - [col_sep]
        Dialect::QUOTE_CHARACTERS.each do |quote_char|
          analysis = self.class.analyze(@sample, col_sep.b,
                                        quote_char.b.ord,
                                        others.map(&:b),
                                        foreign_quote(quote_char).b.ord)
          Dialect::ROW_SEPARATORS.each do |row_sep|
            results[[col_sep, quote_char, row_sep]] =
              score(analysis, row_sep)
          end
        end
      end
      results
    end

    private

    def foreign_quote(quote_char)
      (Dialect::QUOTE_CHARACTERS - [quote_char]).first
    end

    def score(analysis, row_sep)
      non_empty = analysis.rows.reject { |width| width.zero? }
      # The final record is a partial when the sample ends in the
      # middle of a record (the field may continue in unread bytes).
      complete = non_empty.dup
      unless @eof || analysis.ends_on_record_boundary
        complete.pop
      end
      complete = complete.reject { |width| width.zero? }
      frequencies = complete.each_with_object(Hash.new(0)) do |width, counts|
        counts[width] += 1
      end
      dominant_columns, dominant_count = frequencies.max_by { |_, count| count }
      dominant_columns ||= 1
      dominant_count ||= 0
      inconsistent = complete.size - dominant_count
      multicolumn = dominant_columns > 1

      column_score = 0
      if multicolumn
        column_score += dominant_count * dominant_columns * STRUCTURAL_WEIGHT
      end
      column_score -= inconsistent * WIDTH_INCONSISTENCY_PENALTY
      foreign = Dialect::COLUMN_SEPARATORS.sum do |other|
        analysis.foreign_separators[other.b].to_i
      end
      column_score -= foreign * FOREIGN_SEP_PENALTY
      column_score -= ILLEGAL_QUOTE_PENALTY if analysis.hard_error

      # Quote axis: balanced quoted runs confirm the quote character;
      # occurrences of the alternative candidate quote count against it.
      quote_score = analysis.quoted_runs * QUOTED_RUN_SCORE -
        (analysis.foreign_quotes.to_i * ILLEGAL_QUOTE_PENALTY)
      quote_score -= ILLEGAL_QUOTE_PENALTY if analysis.hard_error

      crlf = analysis.newline_counts[CRLF]
      bare_lf = analysis.newline_counts[LF]
      bare_cr = analysis.newline_counts[CR]
      row_score = case row_sep
      when "\r\n"
        (crlf * 3) - (bare_lf + bare_cr)
      when "\n"
        (crlf + bare_lf) - (bare_cr * 2)
      when "\r"
        (crlf + bare_cr) - (bare_lf * 2)
      end * ROW_SEP_WEIGHT

      confirmed = dominant_count >= 2

      {
        analysis: analysis,
        scores: {
          column: column_score,
          quote: quote_score,
          row: row_score,
          total: column_score + quote_score + row_score,
        },
        consistent: inconsistent.zero?,
        dominant_columns: dominant_columns,
        structurally_confirmed: confirmed,
        unclosed_quote: analysis.unclosed_quote,
        ends_with_cr: analysis.ends_with_cr,
        hard_error: analysis.hard_error,
      }
    end
  end
end
