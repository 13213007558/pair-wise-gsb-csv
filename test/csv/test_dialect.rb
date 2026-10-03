# frozen_string_literal: false

require_relative "helper"
require "forwardable"

class TestCSVDialect < Test::Unit::TestCase
  include CSVHelper

  class NonSeekableIO
    extend Forwardable
    def_delegators :@io, :eof?, :gets, :read

    def initialize(data)
      @io = StringIO.new(data)
    end

    def seek
      raise NotImplementedError
    end
    alias_method :rewind, :seek
  end

  class GetsOnlyIO < NonSeekableIO
    undef_method :read
  end

  def test_detects_semicolon_crlf_without_consuming_prefix
    data = "name;value\r\na;b\r\n"
    detection = CSV.detect_dialect(NonSeekableIO.new(data), byte_budget: 32)

    assert_predicate(detection, :confident?)
    assert_equal({
                   col_sep: ";",
                   row_sep: "\r\n",
                   quote_char: nil,
                 },
                 detection.options)
    assert_equal(data[0, 32], detection.prefix)
    assert_equal([
                   ["name", "value"],
                   ["a", "b"],
                 ],
                 CSV.parse(detection.io, **detection.options))
  end

  def test_detects_tab_and_lf
    data = "a\tb\nc\td\n"
    detection = CSV.detect_dialect(StringIO.new(data), byte_budget: 8)

    assert_predicate(detection, :confident?)
    assert_equal("\t", detection.best.col_sep)
    assert_equal("\n", detection.best.row_sep)
  end

  def test_quoted_newline_in_first_row_keeps_valid_interpretations
    data = "a\t\"line one\nline two\"\r\nnext"
    detection = CSV.detect_dialect(StringIO.new(data), byte_budget: 26)

    assert_predicate(detection, :ambiguous?)
    assert_nil(detection.best)
    assert_equal(["\n", "\r\n"],
                 detection.evidence[:components][:row_sep].first(2).map { |item| item[:value] })
    assert_equal(["\t", ","],
                 detection.evidence[:components][:col_sep].first(2).map { |item| item[:value] })
    viable = detection.candidates.select(&:viable?)
    assert(viable.any? { |candidate| candidate.dialect.col_sep == "\t" })
    assert(viable.any? { |candidate| candidate.dialect.row_sep == "\r\n" })
  end

  def test_prefix_ending_in_open_quote_is_not_marked_invalid
    data = "a,b,\"still reading"
    detection = CSV.detect_dialect(NonSeekableIO.new(data + "rest\",next\nx,y"),
                                   byte_budget: data.bytesize)

    assert_predicate(detection, :uncertain?)
    quote_candidates = detection.candidates.select do |candidate|
      candidate.dialect.quote_char == '"'
    end
    assert(quote_candidates.all?(&:viable?))
    assert(quote_candidates.any? { |candidate| candidate.evidence[:open_quoted_field] })
    rows = CSV.parse(detection.io,
                     col_sep: ",",
                     row_sep: "\n",
                     quote_char: '"')
    assert_equal([["a", "b", "still readingrest", "next"], ["x", "y"]], rows)
  end

  def test_gets_only_input_keeps_prefix
    detection = CSV.detect_dialect(GetsOnlyIO.new("a;b\n1;2\n"), byte_budget: 4)

    assert_predicate(detection, :confident?)
    assert_equal(4, detection.prefix_bytes)
    with_chunk_size("1") do
      assert_equal([["a", "b"], ["1", "2"]],
                   CSV.parse(detection.io, **detection.options))
    end
  end

  def test_string_detection_can_be_parsed
    data = "a;b\nc;d\n"
    detection = CSV.detect_dialect(data,
                                   byte_budget: data.bytesize,
                                   col_separators: [";"])

    assert_predicate(detection, :confident?)
    assert_equal([["a", "b"], ["c", "d"]],
                 CSV.parse(detection.io, **detection.options))
  end

  def test_pending_crlf_keeps_ambiguous
    detection = CSV.detect_dialect(StringIO.new("a,b\r"),
                                   byte_budget: 4,
                                   row_separators: ["\r\n", "\r"])

    assert_predicate(detection, :ambiguous?)
    assert_equal(["\r", "\r\n"],
                 detection.evidence[:components][:row_sep].map { |item| item[:value] })
  end

  def test_insufficient_sample_remains_uncertain
    detection = CSV.detect_dialect(StringIO.new("one-value"), byte_budget: 9)

    assert_predicate(detection, :insufficient_sample?)
    assert_nil(detection.best)
    assert_equal(9, detection.prefix_bytes)
  end

  def test_byte_budget_is_bounded
    data = "a,b,c\n" * 100
    detection = CSV.detect_dialect(NonSeekableIO.new(data), byte_budget: 10)

    assert_equal(10, detection.prefix_bytes)
    assert_equal(100, CSV.parse(detection.io, **detection.options).size)
  end

  def test_candidates_include_evidence
    detection = CSV.detect_dialect(StringIO.new("a,b\nc,d\n"), byte_budget: 8)
    candidate = detection.candidates.find do |candidate|
      candidate.dialect.col_sep == "," &&
        candidate.dialect.row_sep == "\n"
    end

    assert(candidate)
    assert_equal(2, candidate.evidence[:completed_rows])
    assert_equal([2, 2], candidate.evidence[:field_counts])
    assert_operator(candidate.score, :>, 0)
  end

  def test_explicit_dialect_candidates
    candidates = [
      {col_sep: "|", row_sep: "\n", quote_char: nil},
      {col_sep: ";", row_sep: "\n", quote_char: nil},
    ]
    detection = CSV.detect_dialect(StringIO.new("a|b\nc|d\n"),
                                   byte_budget: 8,
                                   dialects: candidates)

    assert_predicate(detection, :confident?)
    assert_equal("|", detection.best.col_sep)
    assert_equal(candidates.map { |candidate| candidate[:col_sep] },
                 detection.candidates.map { |candidate| candidate.dialect.col_sep }.uniq)
  end

  def test_rejects_empty_candidate_separator
    assert_raise(ArgumentError) do
      CSV.detect_dialect(StringIO.new("a"),
                         byte_budget: 1,
                         dialects: [{col_sep: "", row_sep: "\n", quote_char: nil}])
    end
  end

  def test_requires_positive_byte_budget
    assert_raise(ArgumentError) do
      CSV.detect_dialect(StringIO.new("a,b"), byte_budget: 0)
    end
  end

  def test_uses_input_encoding_for_candidates
    encoding = Encoding::UTF_16LE
    data = "a;b\nc;d\n".encode(encoding)
    detection = CSV.detect_dialect(StringIO.new(data),
                                   byte_budget: data.bytesize,
                                   col_separators: [";"],
                                   row_separators: ["\n"])

    assert_predicate(detection, :confident?)
    assert_equal(encoding, detection.best.col_sep.encoding)
    rows = CSV.parse(detection.io, **detection.options)
    assert_equal([encoding] * 4, rows.flatten.map(&:encoding))
    assert_equal([["a", "b"], ["c", "d"]],
                 rows.map { |row| row.map { |field| field.encode("UTF-8") } })
  end
end
