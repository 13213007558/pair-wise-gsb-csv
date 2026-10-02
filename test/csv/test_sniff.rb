# -*- coding: utf-8 -*-
# frozen_string_literal: false

require_relative "helper"

class TestCSVSniff < Test::Unit::TestCase
  include CSVHelper

  # A non-seekable IO that yields at most +chunk+ bytes per read and
  # refuses to rewind or seek, like a pipe or socket.
  class ChunkedIO
    def initialize(data, chunk = 3)
      @data = data
      @chunk = chunk
      @pos = 0
    end

    attr_reader :pos

    def read(length = nil)
      length ||= @chunk
      take = [length, @chunk, @data.bytesize - @pos].min
      return nil if take.zero?
      piece = @data.byteslice(@pos, take)
      @pos += take
      piece
    end

    def eof?
      @pos >= @data.bytesize
    end

    def external_encoding
      Encoding::UTF_8
    end

    def rewind
      raise IOError, "non-seekable"
    end
    alias_method :seek, :rewind
  end

  def test_detects_comma_dialect
    result = CSV.sniff("a,b,c\n1,2,3\n")
    assert_equal(",", result.best.col_sep)
    assert_equal('"', result.best.quote_char)
    assert_equal("\n", result.best.row_sep)
    assert_predicate(result, :certain?)
    assert_equal([["a", "b", "c"], ["1", "2", "3"]],
                 result.parse)
  end

  def test_detects_semicolon_with_quoted_decimal_comma
    data = "Produkt;Preis\nApfel;" + '"1,99"' + "\nBrot;" + '"2,50"' + "\n"
    result = CSV.sniff(data)
    assert_equal(";", result.best.col_sep)
    assert_predicate(result, :certain?)
    assert_equal([["Produkt", "Preis"],
                  ["Apfel", "1,99"],
                  ["Brot", "2,50"]],
                 result.parse)
  end

  def test_detects_tab_pipe_and_colon
    assert_equal("\t", CSV.sniff("a\tb\nc\td\n").best.col_sep)
    assert_equal("|", CSV.sniff("a|b\nc|d\n").best.col_sep)
    assert_equal(":", CSV.sniff("a:b\nc:d\n").best.col_sep)
  end

  def test_detects_crlf_and_cr
    assert_equal("\r\n", CSV.sniff("a,b\r\nc,d\r\n").best.row_sep)
    assert_equal("\r", CSV.sniff("a,b\rc,d\r").best.row_sep)
    assert_equal("\n", CSV.sniff("a,b\nc,d\n").best.row_sep)
  end

  def test_single_line_quoted_multicolumn_is_indeterminate_without_rows
    # One record cannot prove a recurring structure.
    result = CSV.sniff('"a,b","c"')
    refute_predicate(result, :certain?)
    assert_equal(",", result.best.col_sep)
    assert_raise(CSV::IndeterminateError) { result.parse }
    assert_equal([["a,b", "c"]], result.parse(force: true))
  end

  def test_quoted_separator_and_newline_are_not_structure
    data = %("a;b\nx;y";c\n"d;e\nf;g";h\n)
    result = CSV.sniff(data)
    assert_equal(";", result.best.col_sep)
    assert_predicate(result, :certain?)
    assert_equal([["a;b\nx;y", "c"], ["d;e\nf;g", "h"]],
                 result.parse)
  end

  def test_text_explained_by_two_dialects_is_ambiguous
    text = "a;b,c\n1;2,3\n"
    result = CSV.sniff(text)
    assert_predicate(result, :ambiguous?)
    refute_predicate(result, :certain?)
    assert_include(result.reasons, :ambiguous_column_separator)

    # Both readings are legitimate, distinct CSV parses.
    assert_equal([["a;b", "c"], ["1;2", "3"]],
                 CSV.parse(text, col_sep: ","))
    assert_equal([["a", "b,c"], ["1", "2,3"]],
                 CSV.parse(text, col_sep: ";"))

    # Comma wins the documented tie-break but is not forced.
    assert_equal(",", result.best.col_sep)
    assert_raise(CSV::IndeterminateError) { result.parse }
    assert_equal([["a;b", "c"], ["1;2", "3"]],
                 result.parse(force: true))
  end

  def test_no_separator_evidence_is_indeterminate_not_comma
    result = CSV.sniff("just plain words\nsecond row here\n")
    refute_predicate(result, :certain?)
    refute_predicate(result, :ambiguous?)
    assert_predicate(result, :indeterminate?)
    assert_include(result.reasons, :insufficient_evidence)
    assert_raise(CSV::IndeterminateError) { result.parse }
  end

  def test_empty_input_is_indeterminate
    result = CSV.sniff("")
    refute_predicate(result, :certain?)
    assert_include(result.reasons, :insufficient_evidence)
  end

  def test_single_record_without_quoting_is_indeterminate
    result = CSV.sniff("one,two,three")
    # A single unquoted line could be one field containing commas.
    refute_predicate(result, :certain?)
  end

  def test_sample_ending_inside_quoted_field_is_truncated
    data = "a,b\nc,d\n" + '"unclosed, field' + ("z" * 100)
    io = ChunkedIO.new(data, 2)
    result = CSV.sniff(io, max_bytes: 24)
    assert_predicate(result, :truncated?)
    refute_predicate(result, :corrupt?)
    refute_predicate(result, :certain?)
    assert_include(result.reasons, :truncated_quoted_field)
  end

  def test_complete_prefix_then_truncated_quoted_field_is_truncated
    data = "a,b\nc,d\n" + '"still open' + ("z" * 100)
    io = ChunkedIO.new(data, 2)
    result = CSV.sniff(io, max_bytes: 18)
    assert_predicate(result, :truncated?)
    assert_equal(",", result.best.col_sep)
  end

  def test_unclosed_quote_at_eof_is_corrupt
    data = "a,b\nc,d\n" + '"unclosed'
    result = CSV.sniff(StringIO.new(data))
    assert_predicate(result, :corrupt?)
    refute_predicate(result, :truncated?)
  end

  def test_mixed_record_separators_is_ambiguous
    result = CSV.sniff("a,b\nc,d\re,f\n")
    assert_include(result.reasons, :ambiguous_row_separator)
    refute_predicate(result, :certain?)
  end

  def test_byte_budget_is_respected_for_chunked_io
    data = "four;five\r\n" * 20
    [1, 5, 33, 100].each do |budget|
      io = ChunkedIO.new(data, 1)
      result = CSV.sniff(io, max_bytes: budget)
      assert_operator(result.bytes_read, :<=, budget)
      assert_equal(result.bytes_read, io.pos)
    end
  end

  def test_non_seekable_io_replays_from_first_byte
    data = %("one,two";three\r\n) + ("four;five\r\n" * 10)
    io = ChunkedIO.new(data, 3)
    result = CSV.sniff(io, max_bytes: 50)
    assert_predicate(result, :certain?)
    assert(result.io.equal?(io) == false) # wrapped, not the raw stream

    rows = result.csv.read
    assert_equal(CSV.parse(data, col_sep: ";", row_sep: "\r\n"), rows)
  end

  def test_non_seekable_io_one_byte_chunks_end_to_end
    data = "id,name\n1," + '"Doe, John"' + "\n2," + '"Roe; Jane"' + "\n"
    io = ChunkedIO.new(data, 1)
    result = CSV.sniff(io, max_bytes: data.bytesize)
    assert_predicate(result, :certain?)
    assert_equal(CSV.parse(data), result.parse)
  end

  def test_non_seekable_io_headers_and_each
    data = "id,name\n1,alice\n2,bob\n"
    io = ChunkedIO.new(data, 2)
    result = CSV.sniff(io, max_bytes: data.bytesize)
    table = result.csv(headers: true).read
    assert_equal([%w[id name], %w[1 alice], %w[2 bob]],
                 [table.headers] + table.map(&:to_h).map(&:values))
  end

  def test_csv_rewind_on_replay_io
    data = "a,b\nc,d\ne,f\n"
    io = ChunkedIO.new(data, 2)
    result = CSV.sniff(io, max_bytes: data.bytesize)
    csv = result.csv
    first = csv.read
    csv.rewind
    second = csv.read
    assert_equal(CSV.parse(data), first)
    assert_equal(first, second)
  end

  def test_multibyte_chunked_replay_preserves_encoding
    data = "名前,値\n鈴木," + '"あ,い"' + "\n田中,うえお\n"
    io = ChunkedIO.new(data, 3)
    result = CSV.sniff(io, max_bytes: data.bytesize)
    assert_predicate(result, :certain?)
    rows = result.parse
    assert_equal(CSV.parse(data), rows)
    assert_equal(Encoding::UTF_8, rows.first.first.encoding)
  end

  def test_result_carries_ranked_candidates_and_evidence
    result = CSV.sniff("a,b\nc,d\n")
    assert_kind_of(Array, result.candidates)
    assert(result.candidates.all? { |d| d.is_a?(CSV::Dialect) })
    assert_kind_of(Hash, result.evidence)
    assert_kind_of(Array, result.evidence[:ranked])
    best_evidence = result.best.evidence
    assert_kind_of(Hash, best_evidence)
    assert_kind_of(Array, best_evidence[:rows])
  end

  def test_dialect_to_options
    dialect = CSV::Dialect.new(col_sep: ";", quote_char: "'",
                               row_sep: "\r\n")
    assert_equal({ col_sep: ";", quote_char: "'", row_sep: "\r\n" },
                 dialect.to_options)
  end

  def test_corrupt_quotes_detected
    # Illegal quoting under both candidate quote characters: a quote
    # lands in the middle of an unquoted field whichever char wins.
    data = "ab\"cd'ef,gh\nij\"kl'mn,op\n"
    result = CSV.sniff(data)
    assert_predicate(result, :corrupt?)
  end
end
