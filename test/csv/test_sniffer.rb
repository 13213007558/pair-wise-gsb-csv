# frozen_string_literal: false

require_relative "helper"

class TestCSVSniffer < Test::Unit::TestCase
  class ChunkIO
    def initialize(data, chunk_size)
      @io = StringIO.new(data.b)
      @chunk_size = chunk_size
    end

    def read(length = nil)
      @io.read(length && [length, @chunk_size].min)
    end

    def eof?
      @io.eof?
    end

    def internal_encoding
      Encoding::UTF_8
    end

    def external_encoding
      Encoding::UTF_8
    end
  end

  def test_detects_column_row_and_quote_dialect
    data = <<~CSV
      "a,b";"x"
      "c,d";"y"
    CSV

    result = CSV.sniff(data)

    assert_equal(:certain, result.status)
    assert_equal(";", result.best.col_sep)
    assert_equal("\n", result.best.row_sep)
    assert_equal('"', result.best.quote_char)
    assert_equal([["a,b", "x"], ["c,d", "y"]], result.reader.to_a)
  end

  def test_reports_equal_evidence_as_uncertain
    data = "a;b,c\nd;e,f\n"

    result = CSV.sniff(data)

    assert_equal(:uncertain, result.status)
    assert_equal("不确定", result.to_s)
    assert_equal(:col_sep, result.ambiguities.first[:dimension])
    assert_equal([",", ";"], result.ambiguities.first[:values])
    assert_nil(result.options)
    assert_raise(ArgumentError) { result.reader }
    semicolon = result.candidates.find { |candidate| candidate.col_sep == ";" }
    assert_equal([["a", "b,c"], ["d", "e,f"]],
                 result.reader(semicolon).to_a)
  end

  def test_does_not_count_separators_inside_quoted_fields
    data = <<~CSV
      "semi;colon";one
      "another;semi";two
    CSV

    result = CSV.sniff(data)

    assert_equal(:certain, result.status)
    assert_equal(";", result.best.col_sep)
    assert_equal(2, result.best.evidence[:embedded_col_separators])
  end

  def test_unclosed_quoted_field_at_eof_is_uncertain
    result = CSV.sniff("a,b\n\"unclosed")

    assert_equal(:uncertain, result.status)
    assert_equal(:damaged_unclosed_quote, result.incomplete_reason)
    rejection = result.rejections.find do |candidate|
      candidate.quote_char == '"' && candidate.col_sep == ","
    end
    assert_equal(:unexpected_quote, rejection.reason)
  end

  def test_unfinished_quoted_field_inside_sample_is_incomplete
    result = CSV.sniff("\"quoted,field\nstill inside\"",
                       byte_budget: 18)

    assert_equal(:uncertain, result.status)
    assert_equal(:unclosed_quote, result.incomplete_reason)
    refute(result.rejections.any? { |candidate| candidate.reason == :unclosed_quote })
  end

  def test_non_seekable_reader_continues_from_original_first_byte
    data = <<~CSV
      "a,b";one
      "c,d";two
    CSV
    io = ChunkIO.new(data, 3)

    result = CSV.sniff(io)

    assert(result.certain?)
    assert_equal(20, result.evidence[:bytes_read])
    assert_equal([["a,b", "one"], ["c,d", "two"]],
                 result.reader.to_a)
  end

  def test_non_seekable_reader_combines_split_multibyte_character
    data = "\u{1F600},b\nx,y\n"
    result = CSV.sniff(ChunkIO.new(data, 1))

    assert(result.certain?)
    assert_equal([["\u{1F600}", "b"], ["x", "y"]],
                 result.reader.to_a)
  end

  def test_detects_crlf
    result = CSV.sniff("a,b\r\nc,d\r\n")

    assert_equal(:certain, result.status)
    assert_equal("\r\n", result.best.row_sep)
  end

  def test_byte_budget_is_observed
    result = CSV.sniff("a,b\nc,d\n", byte_budget: 5)

    assert_equal(:uncertain, result.status)
    assert_equal(5, result.sample_size)
    assert_equal(5, result.byte_budget)
  end
end
