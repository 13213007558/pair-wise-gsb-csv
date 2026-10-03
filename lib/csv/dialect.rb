# frozen_string_literal: true

class CSV
  class Dialect < Struct.new(:col_sep, :row_sep, :quote_char)
    def to_h
      {
        col_sep: col_sep,
        row_sep: row_sep,
        quote_char: quote_char,
      }
    end
    alias_method :to_hash, :to_h
  end

  class DialectCandidate < Struct.new(:dialect, :score, :state, :evidence)
    def viable?
      state == :viable
    end

    def options
      dialect.to_h
    end
  end

  class DialectDetection < Struct.new(:best, :status, :candidates,
                                      :prefix, :prefix_bytes,
                                      :byte_budget, :evidence)
    def confident?
      status == :confident
    end

    def uncertain?
      !confident?
    end

    def ambiguous?
      status == :ambiguous
    end

    def insufficient_sample?
      status == :insufficient_sample
    end

    def options
      best && best.to_h
    end

    def io
      @io
    end

    def to_h
      {
        best: best,
        status: status,
        candidates: candidates,
        prefix: prefix,
        prefix_bytes: prefix_bytes,
        byte_budget: byte_budget,
        evidence: evidence,
      }
    end
    alias_method :to_hash, :to_h

    private

    def attach_io(io)
      @io = io
      self
    end
  end

  class Dialect
    DEFAULT_COL_SEPARATORS = [",", ";", "\t"].freeze
    DEFAULT_ROW_SEPARATORS = ["\r\n", "\n", "\r"].freeze
    DEFAULT_QUOTE_CHARACTERS = ['"', nil].freeze

    class PrefixedIO
      def initialize(prefix, io = nil)
        @prefix = +prefix
        @io = io
        @position = 0
        @all_filled = false
      end

      def pos
        @position
      end

      def seek(position)
        @position = position
      end

      def eof?
        if @io.nil?
          @position >= @prefix.bytesize
        else
          super
        end
      end
      alias_method :eof, :eof?

      def external_encoding
        @prefix.encoding
      end

      def internal_encoding
        nil
      end

      def encoding
        @prefix.encoding
      end

      def to_io
        self
      end

      def close
        @io.close if @io.respond_to?(:close)
      end

      def respond_to_missing?(name, include_private = false)
        @io.respond_to?(name, include_private) || super
      end

      def method_missing(name, *arguments, &block)
        if @io && @io.respond_to?(name)
          @io.public_send(name, *arguments, &block)
        else
          super
        end
      end

      class Readable < self
        def csv_dialect_readable_prefix?
          true
        end

        def read(length = nil, outbuf = nil)
          data = read_virtual(length)
          data = data.dup if data.frozen?
          data.force_encoding(@prefix.encoding) if data.empty?
          outbuf ? outbuf.replace(data) : data
        end

        def gets(separator = $/, length = nil)
          read(length) if need_fill?(length)
          line = virtual_buffer.gets(separator, length)
          @position += line.bytesize if line
          line
        end

        def eof?
          fill_all if @io && @io.respond_to?(:read)
          @position >= virtual_buffer.size
        end
        alias_method :eof, :eof?
      end

      class Streaming < self
        def gets(separator = $/, length = nil)
          while @position < @prefix.bytesize
            available = @prefix.bytesize - @position
            chunk_length = length ? [length, available].min : nil
            line = @prefix.byteslice(@position, chunk_length || available)
            @position += line.bytesize
            return line
          end
          @io.gets(separator, length)
        end

        def eof?
          @position >= @prefix.bytesize && (!@io.respond_to?(:eof?) || @io.eof?)
        end
        alias_method :eof, :eof?
      end

      private

      def need_fill?(length)
        @io && !@all_filled && (length.nil? || @prefix.bytesize < @position + length)
      end

      def fill_all
        unless @all_filled
          rest = @io.read
          @prefix << rest if rest
          @all_filled = true
        end
      end

      def read_virtual(length)
        if need_fill?(length)
          if length.nil?
            fill_all
          else
            wanted = @position + length
            while @prefix.bytesize < wanted
              needed = wanted - @prefix.bytesize
              chunk = @io.read(needed)
              break if chunk.nil?
              @prefix << chunk
              @all_filled = chunk.bytesize < needed
            end
          end
        end
        data = length ? @prefix.byteslice(@position, length) : @prefix.byteslice(@position..-1)
        @position += data.bytesize
        data || ""
      end

      def virtual_buffer
        StringIO.new(@prefix.byteslice(@position..-1) || "")
      end
    end

    class Analysis
      attr_reader :state, :evidence, :error

      def initialize(sample, dialect, complete_input)
        @sample = sample
        @col_sep = dialect.col_sep
        @row_sep = dialect.row_sep
        @quote_char = dialect.quote_char
        @complete_input = complete_input
        @state = :viable
        @error = nil
        @evidence = analyze
      end

      private

      def analyze
        counters = Hash.new(0)
        field_counts = []
        in_quoted_field = false
        field_has_content = false
        field_is_closed_quoted = false
        field_count = 1
        completed_rows = 0
        position = 0
        last_was_row_separator = false

        while position < @sample.bytesize
          if in_quoted_field
            if @quote_char && matches?(position, @quote_char)
              counters[:quote_characters] += 1
              position += @quote_char.bytesize
              if matches?(position, @quote_char)
                counters[:escaped_quote_pairs] += 1
                counters[:quote_characters] += 1
                position += @quote_char.bytesize
                field_has_content = true
              elsif boundary?(position)
                in_quoted_field = false
                field_is_closed_quoted = true
              else
                invalid!(:malformed_quoted_field)
              end
            elsif (separator = row_separator_at(position, true))
              counters[:row_separators_in_quoted_fields] += 1
              position += separator.bytesize
            elsif matches?(position, @col_sep)
              counters[:col_separators_in_quoted_fields] += 1
              position += @col_sep.bytesize
            else
              position += 1
            end
            next
          end

          if (separator = row_separator_at(position, false))
            counters[:row_separators] += 1
            counters[:quoted_fields] += 1 if field_is_closed_quoted
            field_counts << field_count
            completed_rows += 1
            field_count = 1
            field_has_content = false
            field_is_closed_quoted = false
            position += separator.bytesize
            last_was_row_separator = true
          elsif @quote_char && !field_has_content && !field_is_closed_quoted &&
                matches?(position, @quote_char)
            in_quoted_field = true
            counters[:quote_characters] += 1
            position += @quote_char.bytesize
          elsif matches?(position, @col_sep)
            counters[:col_separators] += 1
            counters[:quoted_fields] += 1 if field_is_closed_quoted
            field_count += 1
            field_has_content = false
            field_is_closed_quoted = false
            position += @col_sep.bytesize
            last_was_row_separator = false
          else
            if !@complete_input && @row_sep == "\r\n" &&
               @sample.byteslice(position, 1) == "\r" &&
               position + 1 == @sample.bytesize
              counters[:row_separators] += 1
            end
            break if pending_crlf?(position)
            invalid!(:unexpected_unquoted_newline) if invalid_unquoted_byte?(position)
            field_has_content = true
            position += 1
            last_was_row_separator = false
          end
        end

        counters[:quoted_fields] += 1 if field_is_closed_quoted
        open_quoted_field = in_quoted_field && !@complete_input
        invalid!(:unclosed_quoted_field) if in_quoted_field && @complete_input
        field_counts << field_count unless last_was_row_separator

        evidence = {
          completed_rows: completed_rows,
          field_counts: field_counts,
          open_quoted_field: open_quoted_field,
          pending_row_separator: pending_crlf?(@sample.bytesize),
          counters: counters,
        }
        evidence[:scores] = scores(evidence)
        evidence
      end

      def matches?(position, token)
        token.is_a?(String) && @sample.byteslice(position, token.bytesize) == token
      end

      def boundary?(position)
        position == @sample.bytesize ||
          matches?(position, @col_sep) ||
          matches?(position, "\r\n") ||
          matches?(position, "\n") ||
          (@row_sep == "\r" && matches?(position, "\r")) ||
          (@row_sep == :auto &&
            (matches?(position, "\r\n") ||
             matches?(position, "\n") ||
             matches?(position, "\r"))) ||
          (@row_sep.is_a?(String) && matches?(position, @row_sep))
      end

      def row_separator_at(position, quoted)
        if @row_sep == :auto
          return "\r\n" if matches?(position, "\r\n")
          return "\n" if matches?(position, "\n")
          return "\r" if matches?(position, "\r")
        elsif matches?(position, @row_sep)
          return nil if quoted && pending_crlf?(position)
          return nil if !quoted && @row_sep == "\r" && pending_crlf?(position)
          return @row_sep
        elsif !quoted && @row_sep == "\r\n"
          if matches?(position, "\n")
            invalid!(:unexpected_unquoted_newline)
            return "\n"
          end
        end
        nil
      end

      def pending_crlf?(position)
        !@complete_input &&
          position == @sample.bytesize &&
          position > 0 &&
          @sample.byteslice(-1) == "\r"
      end

      def invalid_unquoted_byte?(position)
        return false unless @row_sep == "\r\n"
        return false if !@complete_input &&
                        @sample.byteslice(position, 1) == "\r" &&
                        position + 1 == @sample.bytesize
        byte = @sample.byteslice(position, 1)
        byte == "\n" ||
          (byte == "\r" && @sample.byteslice(position, 2) != "\r\n" &&
           !pending_crlf?(position))
      end

      def invalid!(error)
        @state = :invalid
        @error = error
      end

      def scores(evidence)
        counters = evidence[:counters]
        col_score = counters[:col_separators] * 3
        col_score += 3 if consistent_rows?(evidence[:field_counts])

        row_score = row_separator_score(counters)

        quote_score = counters[:quoted_fields] * 10
        quote_score += counters[:row_separators_in_quoted_fields] * 5
        quote_score += counters[:escaped_quote_pairs] * 2

        {
          col_sep: col_score,
          row_sep: row_score,
          quote_char: quote_score,
          total: col_score + row_score + quote_score,
        }
      end

      def row_separator_score(counters)
        count = counters[:row_separators]
        count += counters[:row_separators_in_quoted_fields] if @row_sep == :auto
        multiplier = 10
        if pending_crlf?(@sample.bytesize)
          count += 1 if @row_sep == "\r\n" || @row_sep == "\r"
          multiplier = 10
        elsif @row_sep == "\r\n"
          multiplier = 15
        end
        count * multiplier
      end

      def consistent_rows?(field_counts)
        field_counts.size > 1 &&
          field_counts.all? { |count| count > 1 } &&
          field_counts.uniq.size == 1
      end
    end

    class Detector
      def initialize(input, dialects, byte_budget)
        @input = input
        @dialects = dialects
        @byte_budget = byte_budget
        @sample_encoding = input_encoding
      end

      def detect
        prefix, complete_input = read_prefix
        dialects = normalize_dialects(@dialects)
        candidates = dialects.collect do |dialect|
          analysis = Analysis.new(prefix, dialect, complete_input)
          score = analysis.state == :viable ? analysis.evidence[:scores][:total] : -1
          DialectCandidate.new(dialect, score, analysis.state,
                               analysis.evidence.merge(error: analysis.error))
        end.sort_by do |candidate|
          preferred_quote = candidate.dialect.quote_char.nil? ? 0 : 1
          [-candidate.score, preferred_quote, candidate.dialect.to_s]
        end

        selection = select(candidates, prefix, complete_input)
        detection = DialectDetection.new(selection[:best], selection[:status],
                                         candidates, prefix, prefix.bytesize,
                                         @byte_budget, selection[:evidence])
        io_class = @input.respond_to?(:read) ? PrefixedIO::Readable : PrefixedIO::Streaming
        detection.send(:attach_io, io_class.new(prefix, @input))
        detection
      end

      private

      def normalize_dialects(dialects)
        raise ArgumentError, "dialects must not be empty" if dialects.empty?
        sample_encoding = @sample_encoding
        dialects.collect do |dialect|
          case dialect
          when Dialect
            dialect
          when Hash
            col_sep = encode_candidate(dialect.fetch(:col_sep).to_s, sample_encoding)
            row_sep = dialect.fetch(:row_sep)
            row_sep = encode_candidate(row_sep.to_s, sample_encoding) unless row_sep == :auto
            quote_char = dialect.fetch(:quote_char)
            quote_char = encode_candidate(quote_char.to_s, sample_encoding) unless quote_char.nil?
            if col_sep.empty? || row_sep.to_s.empty?
              raise ArgumentError, "separators must not be empty"
            end
            if quote_char && (quote_char.to_s.empty? || quote_char.length != 1)
              raise ArgumentError, "quote_char must be nil or a single character"
            end
            Dialect.new(col_sep, row_sep, quote_char)
          else
            raise ArgumentError, "invalid dialect: #{dialect.inspect}"
          end
        end.uniq(&:to_h)
      end

      def encode_candidate(value, encoding)
        value.encode(encoding)
      rescue Encoding::UndefinedConversionError, Encoding::ConverterNotFoundError
        value
      end

      def read_prefix
        data = read_with_budget
        data.force_encoding(@sample_encoding)
        complete = data.bytesize < @byte_budget
        [data, complete]
      end

      def input_encoding
        if @input.respond_to?(:external_encoding) && @input.external_encoding
          @input.external_encoding
        else
          Encoding::ASCII_8BIT
        end
      end

      def read_with_budget
        if @input.respond_to?(:read)
          @input.read(@byte_budget) || ""
        elsif @input.respond_to?(:gets)
          data = +""
          while data.bytesize < @byte_budget
            chunk = @input.gets(nil, @byte_budget - data.bytesize)
            break if chunk.nil?
            data << chunk
          end
          data
        else
          raise ArgumentError, "input must respond to read or gets"
        end
      end

      def select(candidates, prefix, complete_input)
        viable = candidates.select(&:viable?)
        evidence = {
          sample_bytes: prefix.bytesize,
          complete_input: complete_input,
          components: component_evidence(viable),
        }
        status = status(viable, prefix, evidence)
        best = status == :confident ? viable.first.dialect : nil
        {best: best, status: status, evidence: evidence}
      end

      def component_evidence(candidates)
        [:col_sep, :row_sep, :quote_char].each_with_object({}) do |component, result|
          grouped = candidates.group_by { |candidate| candidate.dialect[component] }
          result[component] = grouped.collect do |value, values|
            component_score = values.collect { |value_candidate|
              value_candidate.evidence[:scores][component]
            }.max
            {value: value, score: component_score, candidates: values}
          end.sort_by do |item|
            preferred_nil_quote = component == :quote_char && item[:value].nil? ? 0 : 1
            [-item[:score], preferred_nil_quote, item[:value].to_s]
          end
        end
      end

      def status(candidates, prefix, evidence)
        return :insufficient_sample if prefix.empty? || candidates.empty?

        components = evidence[:components]
        [:col_sep, :row_sep].each do |component|
          ranked = components[component]
          next if ranked.first[:score].zero? && component == :row_sep &&
                  candidates.any? { |candidate| candidate.evidence[:pending_row_separator] }
          return :insufficient_sample if ranked.first[:score].zero?
        end

        top_score = candidates.first.score
        tied = candidates.select { |candidate| candidate.score == top_score }
        return :ambiguous if tied.map { |candidate| candidate.dialect.col_sep }.uniq.size > 1
        return :ambiguous if tied.map { |candidate| candidate.dialect.row_sep }.uniq.size > 1

        quote_ranked = components[:quote_char]
        if quote_ranked[1] &&
           quote_ranked[1][:score] == quote_ranked.first[:score] &&
           !quote_ranked.first[:score].zero?
          return :ambiguous
        end

        if candidates.any? { |candidate| candidate.evidence[:open_quoted_field] }
          return :ambiguous if components[:quote_char].size > 1
          return :insufficient_sample
        end

        if candidates.any? { |candidate| candidate.evidence[:pending_row_separator] } &&
           components[:row_sep].size > 1
          return :ambiguous
        end

        :confident
      end
    end
  end
end
