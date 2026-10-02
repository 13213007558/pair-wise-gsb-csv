# frozen_string_literal: true

require "stringio"

class CSV
  # A CSV::Dialect describes one way to interpret CSV bytes:
  # the column separator (+col_sep+), quote character (+quote_char+)
  # and record (line) separator (+row_sep+).
  #
  # Dialect objects are returned by CSV.sniff. They are plain
  # value objects and can be turned into parser options with
  # CSV::Dialect#to_options or used directly through
  # CSV::Dialect#new_csv / CSV::Dialect#parse.
  class Dialect
    # Candidate column separators probed by CSV.sniff.
    COLUMN_SEPARATORS = [",", ";", "\t", "|", ":"].freeze

    # Candidate quote characters probed by CSV.sniff.
    QUOTE_CHARACTERS = ['"', "'"].freeze

    # Candidate record separators probed by CSV.sniff.
    ROW_SEPARATORS = ["\r\n", "\n", "\r"].freeze

    # Default byte budget for CSV.sniff: at most this many bytes are
    # consumed from a stream.
    DEFAULT_MAX_BYTES = 65_536

    # How many bytes are pulled from an IO per read while sniffing.
    READ_CHUNK_SIZE = 1024

    # @return [String] the column separator
    attr_reader :col_sep
    # @return [String] the quote character
    attr_reader :quote_char
    # @return [String, Symbol] the record separator (or +:auto+)
    attr_reader :row_sep
    # @return [Hash] the evidence collected for this dialect (scores,
    #   column counts, parsed rows, ...).
    attr_reader :evidence

    def initialize(col_sep:, quote_char:, row_sep:, evidence: {})
      @col_sep = col_sep
      @quote_char = quote_char
      @row_sep = row_sep
      @evidence = evidence
    end

    # @return [Hash] options suitable for CSV.new
    def to_options
      options = {
        col_sep: @col_sep,
        quote_char: @quote_char,
      }
      options[:row_sep] = @row_sep if @row_sep
      options
    end

    # Creates a CSV reader for +data+ using this dialect.
    # Any extra +options+ (e.g. +headers: true+) are merged on top.
    #
    # +data+ may be the replay IO returned by CSV.sniff so that data
    # already consumed while probing is still read from the first byte.
    def new_csv(data, **options)
      CSV.new(data, **to_options.merge(options))
    end

    # Convenience helper: CSV.parse with this dialect.
    def parse(data, **options, &block)
      CSV.parse(data, **to_options.merge(options), &block)
    end

    def ==(other)
      other.is_a?(Dialect) and
        col_sep == other.col_sep and
        quote_char == other.quote_char and
        row_sep == other.row_sep
    end
    alias_method :eql?, :==

    def hash
      [col_sep, quote_char, row_sep].hash
    end

    def inspect
      "#<#{self.class.name} col_sep:#{col_sep.inspect} " \
        "quote_char:#{quote_char.inspect} row_sep:#{row_sep.inspect}>"
    end
  end

  # CSV::SniffResult is returned by CSV.sniff.
  #
  # It carries the ranked dialect candidates, the evidence gathered
  # within the byte budget, and the ambiguities that could not be
  # resolved. Callers decide what to do: use #best (with eyes open),
  # ask for more data, or fail loudly. When the result is certain,
  # #csv / #parse use the winning dialect directly; otherwise they
  # raise CSV::IndeterminateError instead of silently assuming a comma.
  class SniffResult
    # @return [Array<Dialect>] ranked candidates, best first
    attr_reader :candidates
    # @return [Integer] bytes consumed from the source while sniffing
    attr_reader :bytes_read
    # @return [Boolean] whether the end of the source was reached
    attr_reader :eof
    # @return [Boolean] whether the sampled bytes end inside an
    #   unfinished quoted field
    attr_reader :truncated
    # @return [Array<Symbol>] machine-readable reason codes explaining
    #   any remaining uncertainty/ambiguity
    attr_reader :reasons
    # @return [Hash] detailed evidence (per candidate and per axis)
    attr_reader :evidence

    # The re-readable source (a ReplayIO or StringIO) positioned
    # at the first byte, or +nil+ when the source was a String.
    # @return [IO, nil]
    attr_reader :io

    def initialize(candidates:, bytes_read:, eof:, truncated:,
                   reasons:, evidence:, io: nil, data: nil)
      @candidates = candidates
      @bytes_read = bytes_read
      @eof = eof
      @truncated = truncated
      @reasons = reasons
      @evidence = evidence
      @io = io
      @data = data
    end

    # @return [Dialect, nil] the highest ranked candidate, if any
    def best
      @candidates.first
    end

    # @return [Dialect, nil] the resolved dialect when #certain?,
    #   otherwise +nil+
    def resolved
      best if certain?
    end

    # A result is certain only when the winning dialect has
    # unambiguous structural evidence (at least two complete records
    # agreeing on a multi-column shape) and no tie, truncation, or
    # malformed data spoils the decision.
    def certain?
      not(@reasons.any?)
    end

    # @return [Boolean] true when two or more dialects explain the
    #   sample equally well
    def ambiguous?
      @reasons.include?(:ambiguous_column_separator) or
        @reasons.include?(:ambiguous_quote_character) or
        @reasons.include?(:ambiguous_row_separator)
    end

    # @return [Boolean] true when not enough evidence is available
    #   (short/empty input, a single record, an unfinished quoted
    #   field at the budget boundary, ...).
    def indeterminate?
      not(certain? or ambiguous?)
    end

    # @return [Boolean] true when every candidate dialect fails hard on
    #   the sample (illegal quoting in the middle of records, ...).
    #   This is different from #truncated?, which means the sample
    #   merely ends too early.
    def corrupt?
      @reasons.include?(:corrupt)
    end

    # @return [Boolean] true when the sample ends inside an unfinished
    #   quoted field; with more bytes it may become a valid CSV.
    def truncated?
      @truncated
    end

    # Build a reader over the probed source (or over +data+) using the
    # winning dialect.
    #
    # Raises CSV::IndeterminateError when the result is not certain;
    # pass <tt>force: true</tt> to use #best anyway.
    def csv(data = @io, force: false, **options)
      dialect = select_dialect!(force)
      data = @data || data || @io
      raise ArgumentError, "no data available" if data.nil?
      dialect.new_csv(data, **options)
    end

    # Parse the probed source (or +data+) with the winning dialect.
    #
    # Raises CSV::IndeterminateError when the result is not certain;
    # pass <tt>force: true</tt> to use #best anyway.
    def parse(data = @io, force: false, **options, &block)
      dialect = select_dialect!(force)
      data = @data || data || @io
      raise ArgumentError, "no data available" if data.nil?
      dialect.parse(data, **options, &block)
    end

    def inspect
      status = certain? ? "certain" : (ambiguous? ? "ambiguous" : "indeterminate")
      "#<#{self.class.name} #{status} best=#{best&.inspect} " \
        "reasons=#{@reasons.inspect} candidates=#{@candidates.size}>"
    end

    private

    def select_dialect!(force)
      unless certain? or force
        raise IndeterminateError.new("CSV dialect is not certain: " \
                                    "#{@reasons.inspect}; inspect " \
                                    "SniffResult#candidates or provide " \
                                    "more bytes")
      end
      best or raise(IndeterminateError, "no candidate dialect found")
    end
  end

  # Raised by CSV::SniffResult#csv / #parse when the detected dialect
  # is not certain and +force+ wasn't given.
  class IndeterminateError < StandardError
  end

  # Read-only IO wrapper that replays bytes consumed while sniffing
  # and then continues reading from the wrapped, possibly
  # non-seekable, IO. It implements the reading surface the CSV parser
  # uses (+gets+, +eof?+, +read+), encoding accessors and the IO
  # methods CSV delegates.
  class ReplayIO
    extend Forwardable

    def initialize(prefix, io, encoding: nil)
      @encoding = encoding ||
        (io.respond_to?(:external_encoding) ? io.external_encoding : nil)
      prefix_string = (prefix || String.new).b.dup
      tagged = @encoding && prefix_string.dup.force_encoding(@encoding).valid_encoding?
      if tagged
        prefix_string.force_encoding(@encoding)
      else
        # The budget boundary (or an unknown stream encoding) may cut
        # a multibyte character; replay the bytes as binary.
        @encoding = nil
      end
      @original_prefix = prefix_string.freeze
      @buffered = @original_prefix.dup
      @offset = 0
      @io = io
      @io_position = 0
      @carry = String.new(encoding: Encoding::BINARY)
    end

    def external_encoding
      if @encoding
        @encoding
      elsif @io.respond_to?(:external_encoding)
        @io.external_encoding
      end
    end

    def internal_encoding
      @io.internal_encoding if @io.respond_to?(:internal_encoding)
    end

    # IO surface used by CSV delegation; forwarded only when the
    # wrapped IO supports each method (duck-typed streams may not).
    def close; @io.close if @io.respond_to?(:close); end
    def close_read; @io.close_read if @io.respond_to?(:close_read); end
    def close_write; @io.close_write if @io.respond_to?(:close_write); end
    def closed?; @io.respond_to?(:closed?) ? @io.closed? : eof?; end
    def binmode; @io.binmode if @io.respond_to?(:binmode); end
    def fcntl(*args); @io.fcntl(*args); end
    def fileno; @io.fileno if @io.respond_to?(:fileno); end
    def flush; @io.flush if @io.respond_to?(:flush); end
    def fsync; @io.fsync if @io.respond_to?(:fsync); end
    def isatty; @io.isatty if @io.respond_to?(:isatty); end
    alias_method :tty?, :isatty
    def pid; @io.pid if @io.respond_to?(:pid); end
    def reopen(*args); @io.reopen(*args); end
    def sync; @io.sync if @io.respond_to?(:sync); end
    def sync=(value); @io.sync = value if @io.respond_to?(:sync=); end
    def truncate(length); @io.truncate(length); end

    # Mirrors IO#gets: separator +sep+ and optional byte +limit+.
    def gets(sep = $/, limit = nil)
      if sep.is_a?(Integer)
        limit = sep
        sep = $/
      end
      return read(limit) if sep.nil? && limit
      sep = sep.to_s
      return limited_gets(sep, limit) if limit

      @line_buffer ||= String.new(encoding: @encoding || Encoding::BINARY)
      until (index = @line_buffer.index(sep)) || at_eof?
        chunk = read_chunk(nil)
        break if chunk.nil? || chunk.empty?
        append_encoded(@line_buffer, chunk)
      end
      if (index = @line_buffer.index(sep))
        stop = index + sep.bytesize
        line = @line_buffer.byteslice(0, stop)
        @line_buffer = @line_buffer.byteslice(stop..-1)
        return tag(line)
      end
      line = @line_buffer
      @line_buffer = String.new(encoding: @encoding || Encoding::BINARY)
      line.empty? ? nil : tag(line)
    end

    def read(length = nil, buffer = nil)
      data = String.new(encoding: @encoding || Encoding::BINARY)
      remaining = length
      until (length && remaining.zero?) || at_eof?
        chunk = read_chunk(remaining)
        break if chunk.nil? || chunk.empty?
        data << chunk
        remaining -= chunk.bytesize if length
      end
      buffer&.replace(data)
      data
    end

    def eof?
      buffered_exhausted? &&
        (@io.nil? || !@io.respond_to?(:eof?) || @io.eof?)
    end
    alias_method :eof, :eof?

    # Logical byte position across replayed prefix and wrapped IO.
    def pos
      io_pos = @io.respond_to?(:pos) ? @io.pos : @io_position
      @original_prefix.bytesize - pending_bytes + io_pos
    end
    alias_method :tell, :pos

    def pos=(position)
      seek(position)
    end

    def seek(position, whence = IO::SEEK_SET)
      target = case whence
               when IO::SEEK_SET then position
               when IO::SEEK_CUR then pos + position
               else raise IOError, "unsupported seek whence"
               end
      raise Errno::EINVAL if target < 0
      if target <= @original_prefix.bytesize
        @buffered = @original_prefix.byteslice(target..-1).to_s
        @offset = 0
        @carry = String.new(encoding: Encoding::BINARY)
        @line_buffer = nil
        @io_position = 0
      else
        @buffered = String.new.b
        @offset = 0
        @carry = String.new(encoding: Encoding::BINARY)
        @line_buffer = nil
        move_io_to(target - @original_prefix.bytesize)
      end
      0
    end

    def rewind
      @buffered = @original_prefix.dup
      @offset = 0
      @carry = String.new(encoding: Encoding::BINARY)
      @line_buffer = nil
      @io_position = 0
      0
    end

    def string
      @io.string if @io.respond_to?(:string)
    end

    private

    def limited_gets(_sep, limit)
      data = read(limit)
      return nil if data.nil? || data.empty?
      tag(data)
    end

    def append_encoded(buffer, chunk)
      buffer.force_encoding(Encoding::BINARY) if buffer.encoding != chunk.encoding
      buffer << chunk
    end

    def tag(string)
      return string unless @encoding
      if string.dup.force_encoding(@encoding).valid_encoding?
        string.force_encoding(@encoding)
      else
        string
      end
    end

    # Like #take but, under a declared multibyte encoding, never ends a
    # returned chunk in the middle of a character. The dangling lead
    # bytes are buffered and completed by the next read, which is what
    # lets a few-bytes-at-a-time IO stay encoding-valid at the seam
    # between the sniffed prefix and the live stream.
    def read_chunk(nbytes)
      return take(nbytes) unless @encoding

      out = String.new(encoding: Encoding::BINARY)
      unless @carry.empty?
        out << @carry
        @carry = String.new(encoding: Encoding::BINARY)
      end

      loop do
        enough = nbytes ? out.bytesize >= nbytes : !out.empty?
        break if enough || at_eof?
        room = nbytes ? nbytes - out.bytesize : nil
        raw = take(room)
        break if raw.nil? || raw.empty?
        out.force_encoding(Encoding::BINARY) << raw
        break if nbytes
      end

      return nil if out.empty? && at_eof?

      if out.dup.force_encoding(@encoding).valid_encoding?
        return out.force_encoding(@encoding)
      end

      cut = multibyte_split(out)
      if cut && cut > 0
        complete = out.byteslice(0, cut)
        @carry = out.byteslice(cut..-1).b + @carry
        return complete.force_encoding(@encoding)
      end

      # Whole chunk is one incomplete multibyte character: read until
      # it completes. A bounded read may then return a little more than
      # requested, which is harmless (the parser only joins chunks).
      until out.dup.force_encoding(@encoding).valid_encoding? || at_eof?
        more = take(nil)
        break if more.nil? || more.empty?
        out.force_encoding(Encoding::BINARY) << more.b
      end
      if out.dup.force_encoding(@encoding).valid_encoding?
        out.force_encoding(@encoding)
      else
        # Truly invalid trailing bytes at EOF: pass them through raw.
        out.force_encoding(Encoding::BINARY)
      end
    end

    # Returns the byte length of the longest valid-prefix of +bytes+
    # under @encoding (0 when the very first byte is already bad).
    def multibyte_split(bytes)
      binary = bytes.b
      binary.bytesize.downto(0) do |length|
        return length if length.zero?
        candidate = binary.byteslice(0, length)
        return length if candidate.force_encoding(@encoding).valid_encoding?
      end
    end

    def buffered_exhausted?
      @offset >= @buffered.bytesize
    end

    def pending_bytes
      [@buffered.bytesize - @offset, 0].max
    end

    # Up to +nbytes+ bytes (nil == any amount from one source read),
    # draining the replay buffer before the wrapped IO.
    def take(nbytes)
      unless buffered_exhausted?
        available = @buffered.bytesize - @offset
        count = (nbytes.nil? || nbytes > available) ? available : nbytes
        piece = @buffered.byteslice(@offset, count)
        @offset += count
        return piece
      end
      return nil if @io.nil?
      io_read(nbytes)
    end

    def at_eof?
      buffered_exhausted? &&
        (@io.nil? || !@io.respond_to?(:eof?) || @io.eof?)
    end

    def io_read(nbytes)
      count = nbytes || Dialect::READ_CHUNK_SIZE
      chunk = if @io.respond_to?(:read)
                @io.read(count)
              else
                @io.gets(nil, count)
              end
      @io_position += chunk.bytesize if chunk
      chunk
    end

    def move_io_to(position)
      if @io.respond_to?(:seek)
        @io.seek(position)
        @io_position = position
      else
        skip = position - @io_position
        while skip > 0
          chunk = io_read(skip)
          break if chunk.nil? || chunk.empty?
          skip -= chunk.bytesize
        end
      end
    end
  end
end

require_relative "dialect_sniffer"
require_relative "dialect_probe"
