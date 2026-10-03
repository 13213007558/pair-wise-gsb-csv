# frozen_string_literal: true

class CSV
  # A CSV::Dialect describes one separator combination of a CSV document:
  # the column separator, the quote character and the row separator.
  #
  # Dialect objects are produced by CSV.sniff and can be turned into
  # CSV.new options with #to_options.
  class Dialect
    attr_reader :col_sep, :quote_char, :row_sep

    def initialize(col_sep:, quote_char:, row_sep:)
      @col_sep = col_sep
      @quote_char = quote_char
      @row_sep = row_sep
    end

    def to_options
      {
        col_sep: col_sep,
        quote_char: quote_char,
        row_sep: row_sep,
      }
    end

    def ==(other)
      other.is_a?(Dialect) and other.to_options == to_options
    end
    alias_method :eql?, :==

    def hash
      to_options.hash
    end

    def inspect
      "#<CSV::Dialect col_sep:#{col_sep.inspect} " \
        "row_sep:#{row_sep.inspect} quote_char:#{quote_char.inspect}>"
    end
  end

  # CSV::DialectSniffer guesses the CSV::Dialect of an input by scanning a
  # bounded sample of it against a caller supplied set of candidate
  # separators.  Use CSV.sniff instead of building a sniffer by hand.
  #
  # The sniffer never rewinds the input: whatever it reads while sampling
  # is kept and replayed by the IO object exposed through the result, so
  # non-seekable inputs (pipes, sockets, ...) do not lose their first
  # record.
  class DialectSniffer
    # Raised when a Result cannot provide a dialect to parse with.
    class Error < StandardError
    end

    DEFAULT_COL_SEPS = [",", ";", "\t", "|"].freeze
    DEFAULT_QUOTE_CHARS = ['"', "'"].freeze
    DEFAULT_ROW_SEPS = ["\r\n", "\n", "\r"].freeze
    DEFAULT_SAMPLE_SIZE = 8 * 1024

    # A Candidate pairs a Dialect with the score it earned while scanning
    # the sample and the human readable evidence backing that score.
    class Candidate
      attr_reader :dialect, :score, :evidence

      def initialize(dialect, score, evidence)
        @dialect = dialect
        @score = score
        @evidence = evidence.freeze
      end

      def col_sep
        dialect.col_sep
      end

      def quote_char
        dialect.quote_char
      end

      def row_sep
        dialect.row_sep
      end
    end

    # The outcome of a sniffing run.
    #
    # * #candidates lists every evaluated dialect, best first, each with
    #   its score and evidence.
    # * #dialects lists the plausible dialects: every candidate tied at
    #   the top score.  It holds one entry when the result is certain and
    #   several when the sample cannot discriminate between them.
    # * #status is +:certain+, +:ambiguous+ or +:insufficient+.
    # * #sample returns the bytes consumed from the input while sniffing.
    # * #io returns an IO that replays #sample and then continues reading
    #   the original input, so nothing read while sniffing is lost.
    class Result
      attr_reader :candidates, :sample

      def initialize(candidates, sample, input)
        @candidates = candidates.freeze
        @sample = sample
        @input = input
        @io = nil
      end

      def status
        return :insufficient if dialects.empty?
        return :certain if dialects.size == 1

        :ambiguous
      end

      def certain?
        status == :certain
      end

      def ambiguous?
        status == :ambiguous
      end

      def insufficient?
        status == :insufficient
      end

      def dialects
        @dialects ||= compute_dialects
      end

      def best
        dialects.first
      end

      def io
        @io ||= build_io
      end

      # Builds a CSV over #io using the best dialect.  Extra +options+
      # (for example <tt>headers: true</tt>) are forwarded to CSV.new and
      # take precedence over the detected dialect.  Raises
      # DialectSniffer::Error when the sample was insufficient.
      def csv(**options)
        dialect = best
        if dialect.nil?
          raise Error,
                "no dialect matched the sample; " \
                "increase :sample_size or pass explicit options to CSV.new"
        end
        CSV.new(io, **dialect.to_options.merge(options))
      end

      private

      def compute_dialects
        top = @candidates.first
        return [].freeze if top.nil? or top.score <= 0

        @candidates.take_while do |candidate|
          candidate.score == top.score
        end.map(&:dialect).freeze
      end

      def build_io
        if @input.is_a?(String)
          StringIO.new(@input)
        else
          PrefixIO.new(@sample, @input)
        end
      end
    end

    # PrefixIO replays the bytes consumed while sniffing (+prefix+) and
    # then transparently delegates to the underlying input.  It implements
    # the small IO subset the CSV parser relies on, so a sniffed stream
    # can be parsed without losing its first record even when the stream
    # itself cannot be rewound.
    class PrefixIO
      CHUNK_SIZE = 8192

      def initialize(prefix, input)
        @prefix = prefix.dup
        @buffer = @prefix.dup
        @input = input
      end

      def gets(*args)
        separator, limit = normalize_gets_arguments(args)
        return read(limit) if separator.nil?

        line = nil
        loop do
          line_size = line ? line.bytesize : 0
          remaining = limit && (limit - line_size)
          return line if remaining && remaining <= 0

          index = @buffer.index(separator)
          if index.nil?
            next if fill_buffer(remaining)
            return line if @buffer.empty?

            take = remaining ? [remaining, @buffer.bytesize].min : @buffer.bytesize
            chunk = @buffer.slice!(0, take)
            line = line ? line << chunk : chunk
            return line
          else
            take = index + separator.bytesize
            take = remaining if remaining && remaining < take
            chunk = @buffer.slice!(0, take)
            line = line ? line << chunk : chunk
            return line
          end
        end
      end

      def read(length = nil, outbuf = nil)
        if length.nil?
          data = @buffer.slice!(0, @buffer.bytesize)
          while (chunk = read_chunk(nil))
            data << chunk
          end
        else
          length = Integer(length)
          return outbuf ? outbuf.replace(+"") : +"" if length.zero?

          data = nil
          loop do
            data_size = data ? data.bytesize : 0
            break if data_size >= length
            break if @buffer.empty? && !fill_buffer(length - data_size)
            chunk = @buffer.slice!(0, [@buffer.bytesize, length - data_size].min)
            data = data ? data << chunk : chunk
          end
          if data.nil?
            outbuf&.replace(+"")
            return nil
          end
        end
        if outbuf
          outbuf.replace(data)
          outbuf
        else
          data
        end
      end

      def each_line(*args)
        return enum_for(__method__, *args) unless block_given?

        while (line = gets(*args))
          yield line
        end
        self
      end

      def eof?
        @buffer.empty? && input_eof?
      end
      alias_method :eof, :eof?

      def rewind
        @input.rewind
        @buffer = @prefix.dup
        0
      end

      def close
        @input.close if @input.respond_to?(:close)
        nil
      end

      def closed?
        @input.respond_to?(:closed?) ? @input.closed? : false
      end

      def external_encoding
        @input.external_encoding if @input.respond_to?(:external_encoding)
      end

      def internal_encoding
        @input.internal_encoding if @input.respond_to?(:internal_encoding)
      end

      def encoding
        @input.encoding if @input.respond_to?(:encoding)
      end

      def set_encoding(*args)
        @input.set_encoding(*args) if @input.respond_to?(:set_encoding)
      end

      private

      def normalize_gets_arguments(args)
        separator = $/
        limit = nil
        args.each do |arg|
          case arg
          when Integer
            limit = arg
          when nil
            separator = nil
          else
            separator = arg
          end
        end
        [separator, limit]
      end

      def fill_buffer(limit)
        chunk = read_chunk(limit || CHUNK_SIZE)
        return false if chunk.nil?

        @buffer << chunk
        true
      end

      def read_chunk(limit)
        chunk =
          if @input.respond_to?(:gets)
            limit ? @input.gets(nil, limit) : @input.gets(nil)
          elsif @input.respond_to?(:read)
            @input.read(limit)
          else
            raise IOError, "input must respond to #gets or #read"
          end
        chunk unless chunk.nil? || chunk.empty?
      end

      def input_eof?
        if @input.respond_to?(:eof?)
          @input.eof?
        elsif @input.respond_to?(:eof)
          @input.eof
        else
          false
        end
      end
    end

    def self.sniff(input, **options)
      new(**options).sniff(input)
    end

    def initialize(col_seps: DEFAULT_COL_SEPS,
                   quote_chars: DEFAULT_QUOTE_CHARS,
                   row_seps: DEFAULT_ROW_SEPS,
                   sample_size: DEFAULT_SAMPLE_SIZE)
      @col_seps = validate_candidates(:col_seps, col_seps)
      @quote_chars = validate_candidates(:quote_chars, quote_chars,
                                         allow_nil: true)
      @row_seps = validate_candidates(:row_seps, row_seps)
      unless sample_size.nil? || (sample_size.is_a?(Integer) && sample_size > 0)
        raise ArgumentError, ":sample_size must be a positive Integer or nil"
      end
      @sample_size = sample_size
    end

    def sniff(input)
      sample = read_sample(input)
      candidates = []
      @row_seps.each do |row_sep|
        @col_seps.each do |col_sep|
          @quote_chars.each do |quote_char|
            candidates << evaluate(sample, col_sep, quote_char, row_sep)
          end
        end
      end
      ranked = candidates.sort_by.with_index do |candidate, index|
        [-candidate.score, index]
      end
      Result.new(ranked, sample, input)
    end

    private

    def validate_candidates(name, values, allow_nil: false)
      values = values.to_a
      if values.empty?
        raise ArgumentError, "#{name} must list at least one candidate"
      end
      values.each do |value|
        next if allow_nil && value.nil?
        unless value.is_a?(String) && !value.empty?
          raise ArgumentError, "#{name} entries must be non-empty Strings"
        end
      end
      values.freeze
    end

    def read_sample(input)
      if input.is_a?(String)
        if @sample_size
          input.byteslice(0, @sample_size) || +""
        else
          input.dup
        end
      elsif input.respond_to?(:read)
        input.read(@sample_size) || +""
      elsif input.respond_to?(:gets)
        if @sample_size
          input.gets(nil, @sample_size) || +""
        else
          input.gets(nil) || +""
        end
      else
        raise ArgumentError, "input must be a String or respond to #read/#gets"
      end
    end

    # Scans +sample+ byte by byte assuming the given separator
    # combination, then grades how well the combination explains the
    # sample.  The scan never fails: a sample cut in the middle of a
    # quoted field is reported as truncated evidence, not as an error.
    def evaluate(sample, col_sep, quote_char, row_sep)
      dialect = Dialect.new(col_sep: col_sep,
                            quote_char: quote_char,
                            row_sep: row_sep)
      bytes = sample.b
      col_sep_bytes = col_sep.b
      row_sep_bytes = row_sep.b
      quote_bytes = quote_char && quote_char.b

      field_counts = []
      fields = 1
      quotes_seen = 0
      stray_separators = 0
      in_quotes = false
      offset = 0
      size = bytes.bytesize
      while offset < size
        if in_quotes
          if match?(bytes, offset, quote_bytes)
            if match?(bytes, offset + quote_bytes.bytesize, quote_bytes)
              offset += quote_bytes.bytesize * 2
            else
              in_quotes = false
              quotes_seen += 1
              offset += quote_bytes.bytesize
            end
          else
            offset += 1
          end
        elsif match?(bytes, offset, row_sep_bytes)
          stray_separators += 1 if stray_separator?(bytes, offset, row_sep_bytes)
          field_counts << fields
          fields = 1
          offset += row_sep_bytes.bytesize
        elsif match?(bytes, offset, col_sep_bytes)
          fields += 1
          offset += col_sep_bytes.bytesize
        elsif quote_bytes && match?(bytes, offset, quote_bytes)
          in_quotes = true
          quotes_seen += 1
          offset += quote_bytes.bytesize
        else
          offset += 1
        end
      end

      score, evidence = grade(field_counts, stray_separators,
                              quotes_seen, quote_char, in_quotes)
      Candidate.new(dialect, score, evidence)
    end

    def grade(field_counts, stray_separators, quotes_seen, quote_char,
              truncated)
      score = 0
      evidence = []
      complete_rows = field_counts.size
      if complete_rows.zero?
        evidence << "no complete row found in the sample"
      else
        evidence << "#{complete_rows} complete " \
                    "#{plural(complete_rows, 'row')} in the sample"
        score += complete_rows * 10

        multi_field_rows = field_counts.count { |count| count > 1 }
        if multi_field_rows > 0
          evidence << "#{multi_field_rows} " \
                      "#{plural(multi_field_rows, 'row')} split into " \
                      "multiple fields"
          score += multi_field_rows * 20
        end

        widths = field_counts.uniq
        if widths.size == 1
          evidence << "every complete row has #{widths.first} " \
                      "#{plural(widths.first, 'field')}"
          score += 10
          score += 30 if widths.first > 1
        else
          evidence << "field count varies across rows " \
                     "(#{widths.sort.join(', ')})"
        end

        if stray_separators > 0
          evidence << "#{stray_separators} " \
                      "#{plural(stray_separators, 'row separator')} look " \
                      "like part of a longer \"\\r\\n\" separator"
          score -= stray_separators * 2
        end
      end

      if quote_char
        if quotes_seen.zero?
          evidence << "quote character #{quote_char.inspect} never " \
                      "appears in the sample"
        else
          evidence << "quote character #{quote_char.inspect} appears " \
                      "in the sample"
          score += 5
        end
      end

      if truncated
        evidence << "sample ends inside a quoted field " \
                    "(truncated sample, not malformed data)"
      end

      [score, evidence]
    end

    def plural(count, noun)
      count == 1 ? noun : "#{noun}s"
    end

    def match?(bytes, offset, token)
      bytes.byteslice(offset, token.bytesize) == token
    end

    # Detects a "\r" left dangling before a "\n" row separator (or the
    # reverse), a hint that the real row separator is "\r\n".
    def stray_separator?(bytes, offset, row_sep)
      if row_sep == "\n".b
        offset > 0 && bytes.getbyte(offset - 1) == 0x0D
      elsif row_sep == "\r".b
        bytes.getbyte(offset + 1) == 0x0A
      else
        false
      end
    end
  end

  # Guesses the CSV::Dialect of +input+.
  #
  # +input+ may be a String or any object responding to #read or #gets
  # (it does not need to be seekable).  At most +sample_size+ bytes are
  # consumed for detection; pass nil to read the whole input.
  #
  #   result = CSV.sniff(io, col_seps: [",", ";", "\t"],
  #                          row_seps: ["\r\n", "\n"],
  #                          sample_size: 4096)
  #   result.status      # => :certain, :ambiguous or :insufficient
  #   result.best        # => #<CSV::Dialect ...> or nil
  #   result.candidates  # => every candidate, with score and evidence
  #   csv = result.csv(headers: true)  # parses from the very first byte
  #
  # Candidate lists are evaluated in the given order, which is also the
  # preference order used to break ties for Result#best.
  def self.sniff(input, **options)
    DialectSniffer.sniff(input, **options)
  end
end
