# frozen_string_literal: true

class CSV
  class Sniffer
    Candidate = Struct.new(:col_sep, :row_sep, :quote_char, :score,
                           :evidence, keyword_init: true) do
      def to_h
        {col_sep: col_sep, row_sep: row_sep, quote_char: quote_char}
      end
    end

    Rejection = Struct.new(:col_sep, :row_sep, :quote_char, :reason,
                           :position, keyword_init: true)

    class Result
      attr_reader :sample_size, :byte_budget, :candidates, :rejections,
                  :incomplete_reason, :ambiguities, :evidence

      def initialize(sample_size:, byte_budget:, candidates:, rejections:,
                     incomplete_reason:, ambiguities:, evidence:, reader: nil)
        @sample_size = sample_size
        @byte_budget = byte_budget
        @candidates = candidates
        @rejections = rejections
        @incomplete_reason = incomplete_reason
        @ambiguities = ambiguities
        @evidence = evidence
        @reader = reader
      end

      def certain?
        !uncertain?
      end

      def uncertain?
        best.nil? || !@incomplete_reason.nil? || !@ambiguities.empty?
      end

      def invalid?
        @candidates.empty?
      end

      def best
        @candidates.first
      end

      def dialect
        best unless uncertain?
      end

      def options
        dialect&.to_h
      end

      def reader(candidate = nil)
        if invalid? || !@incomplete_reason.nil?
          raise ArgumentError, "cannot create a reader without sufficient evidence"
        end
        if candidate.nil?
          raise ArgumentError, "choose a candidate from ambiguities" unless @ambiguities.empty?
          candidate = best
        end
        @reader.call(candidate)
      end

      def status
        if invalid?
          :invalid
        elsif uncertain?
          :uncertain
        else
          :certain
        end
      end

      def to_h
        {status: status,
         best: best,
         candidates: candidates,
         ambiguities: ambiguities,
         incomplete_reason: incomplete_reason,
         evidence: evidence,
         rejections: rejections,
         sample_size: sample_size,
         byte_budget: byte_budget}
      end

      def to_s
        uncertain? ? "不确定" : super
      end
    end
 
    class Evaluation
      attr_reader :records, :row_ends, :quoted_fields, :escaped_quotes,
                  :raw_quotes, :embedded_col_seps, :embedded_row_seps,
                  :stray_row_separators,
                  :incomplete_reason, :incomplete_position,
                  :error_position, :error_reason
 
      def initialize(sample, col_sep, row_sep, quote_char, complete_input:)
        @sample = sample
        @col_sep = col_sep
        @row_sep = row_sep
        @quote_char = quote_char
        @records = []
        @row_ends = 0
        @quoted_fields = 0
        @escaped_quotes = 0
        @raw_quotes = 0
        @embedded_col_seps = 0
        @embedded_row_seps = 0
        @stray_row_separators = 0
        @incomplete_reason = nil
        @incomplete_position = nil
        @error_position = nil
        @error_reason = nil
        @fields = 0
        @field_started = false
        @quoted_field = false
        @complete_input = complete_input
        run
      end
 
      def valid?
        @error_reason.nil?
      end
 
      private
      def run
        position = 0
        state = :field_start
        quoted = false
 
        while position < @sample.bytesize
          if quoted
            if starts_at?(@quote_char, position)
              @raw_quotes += 1
              if starts_at?(@quote_char * 2, position)
                @escaped_quotes += 1
                position += @quote_char.bytesize * 2
              elsif closes_quoted_field?(position + @quote_char.bytesize)
                quoted = false
                @quoted_field = true
                state = :quoted_end
                position += @quote_char.bytesize
              else
                malformed(position, :unescaped_quote)
                return
              end
            elsif starts_at?(@row_sep, position)
              @embedded_row_seps += 1
              position += @row_sep.bytesize
            elsif starts_at?(@col_sep, position)
              @embedded_col_seps += 1
              position += @col_sep.bytesize
            else
              position += 1
            end
            next
          end
 
          if @quote_char && state == :field_start &&
             starts_at?(@quote_char, position)
            @raw_quotes += 1
            quoted = true
            state = :quoted
            position += @quote_char.bytesize
          elsif starts_at?(@row_sep, position)
            end_record
            position += @row_sep.bytesize
            state = :field_start
          elsif starts_at?(@col_sep, position)
            @fields += 1
            @field_started = true
            position += @col_sep.bytesize
            state = :field_start
          elsif @quote_char && state == :quoted_end
            malformed(position, :data_after_quoted_field)
            return
          elsif @quote_char && starts_at?(@quote_char, position)
            malformed(position, :unexpected_quote)
            return
          else
            @field_started = true
            state = :unquoted
            byte = @sample.byteslice(position, 1)
            if @quote_char.nil? &&
               byte == "\n".b && @row_sep == "\r\n".b
              malformed(position, :unexpected_row_separator)
              return
            elsif @quote_char.nil? &&
                  byte == "\r".b && @row_sep == "\r\n".b &&
                  !starts_at?("\r\n".b, position)
              malformed(position, :unexpected_row_separator)
              return
            end
            if ((byte == "\r".b && !starts_at?(@row_sep, position) &&
                 @row_sep != "\r".b) ||
                (byte == "\n".b && @row_sep != "\n".b))
              @stray_row_separators += 1
            end
            position += 1
          end
        end
 
        if quoted
          if @complete_input
            malformed(position - @quote_char.bytesize, :unclosed_quote)
          else
            pending(:unclosed_quote, position - @quote_char.bytesize)
          end
        elsif state == :field_start && @field_started
          @records << @fields
        elsif state != :field_start
          pending(:unfinished_record, position)
        end
      end
 
      def end_record
        @row_ends += 1
        @records << @fields + 1
        @fields = 0
        @field_started = false
        if @quoted_field
          @quoted_fields += 1
          @quoted_field = false
        end
      end
 
      def closes_quoted_field?(position)
        starts_at?(@col_sep, position) ||
          starts_at?(@row_sep, position)
      end
 
      def starts_at?(string, position)
        @sample.byteslice(position, string.bytesize) == string
      end
 
      def pending(reason, position)
        @incomplete_reason = reason
        @incomplete_position = position
      end
 
      def malformed(position, reason)
        @error_position = position
        @error_reason = reason
      end
    end
 
    DEFAULT_COL_SEPARATORS = [",", ";", "\t", "|", ":"].freeze
    DEFAULT_QUOTE_CHARACTERS = ['"', "'", nil].freeze
    DEFAULT_ROW_SEPARATORS = ["\r\n", "\n", "\r"].freeze
 
    def self.sniff(input, **options)
      new(**normalize_options(options)).sniff(input)
    end
 
    def initialize(byte_budget: 4096,
                   col_separators: DEFAULT_COL_SEPARATORS,
                   quote_characters: DEFAULT_QUOTE_CHARACTERS,
                   row_separators: DEFAULT_ROW_SEPARATORS)
      @byte_budget = byte_budget
      @col_separators = Array(col_separators)
      @quote_characters = Array(quote_characters)
      @row_separators = Array(row_separators)
      validate_configuration
    end
 
    def self.normalize_options(options)
      options = options.dup
      options[:col_separators] ||= options.delete(:col_seps) ||
                                  options.delete(:col_sep)
      options[:quote_characters] ||= options.delete(:quote_chars) ||
                                    options.delete(:quote_char)
      options[:row_separators] ||= options.delete(:row_seps) ||
                                   options.delete(:row_sep)
      options
    end
 
    def sniff(input)
      @sample, @input, @complete_input, @replay_sample = read_sample(input)
      evaluations = evaluate(@sample.b)
      candidates = build_candidates(evaluations)
      incomplete = incomplete_reason(evaluations, candidates, rejections(evaluations))
      ambiguities = detect_ambiguities(candidates, incomplete)
      result = Result.new(sample_size: @sample.bytesize,
                          byte_budget: @byte_budget,
                          candidates: candidates,
                          rejections: rejections(evaluations),
                          incomplete_reason: incomplete,
                          ambiguities: ambiguities,
                          evidence: evidence(evaluations, candidates),
                          reader: ->(candidate) { open(result, candidate) })
      @last_result = result
      result
    end

    def open(result = @last_result, candidate = result.best)
      if result.invalid? || !result.incomplete_reason.nil?
        raise ArgumentError, "cannot open without sufficient evidence"
      end
      options = candidate.to_h
      if @input.is_a?(String)
        CSV.new(@input, **options)
      else
        CSV.new(BufferedIO.new(@input, @replay_sample, @complete_input,
                               encoding_for(@input)), **options)
      end
    end
 
    private
    def validate_configuration
      unless @byte_budget.is_a?(Integer) && @byte_budget > 0
        raise ArgumentError, "byte_budget must be a positive Integer"
      end
      [@col_separators, @quote_characters.compact, @row_separators].each do |values|
        values.each do |value|
          unless value.is_a?(String) && !value.empty?
            raise ArgumentError, "separators must be non-empty Strings"
          end
        end
      end
    end
 
    def read_sample(input)
      if input.is_a?(String)
        sample = input.byteslice(0, @byte_budget).dup
        [sample, input, sample.bytesize == input.bytesize, sample]
      elsif input.respond_to?(:read)
        sample = +""
        complete = false
        while sample.bytesize < @byte_budget
          chunk = input.read(@byte_budget - sample.bytesize)
          if chunk.nil? || chunk.empty?
            complete = true
            break
          end
          sample << chunk
        end
        complete = true if !complete && input.respond_to?(:eof?) && input.eof?
        analysis_sample = sample.byteslice(0, @byte_budget)
        [analysis_sample, input, complete, sample]
      elsif input.respond_to?(:gets)
        sample = +""
        complete = false
        while sample.bytesize < @byte_budget
          chunk = input.gets(nil, @byte_budget - sample.bytesize)
          if chunk.nil? || chunk.empty?
            complete = true
            break
          end
          sample << chunk
          if input.respond_to?(:eof?) && input.eof?
            complete = true
            break
          end
        end
        analysis_sample = sample.byteslice(0, @byte_budget)
        [analysis_sample, input, complete, sample]
      else
        raise ArgumentError, "input must be a String or readable IO"
      end
    end
 
    def evaluate(sample)
      @col_separators.product(@row_separators, @quote_characters).map do |col_sep, row_sep, quote_char|
        config = {col_sep: col_sep, row_sep: row_sep, quote_char: quote_char}
        if incompatible?(col_sep, row_sep, quote_char)
          [config, Rejection.new(**config, reason: :incompatible, position: nil)]
        else
          [config,
           Evaluation.new(sample, col_sep.b, row_sep.b, quote_char&.b,
                          complete_input: @complete_input)]
        end
      end
    end
 
    def incompatible?(col_sep, row_sep, quote_char)
      col_sep == row_sep || quote_char == col_sep || quote_char == row_sep
    end
 
    def encoding_for(io)
      if io.respond_to?(:internal_encoding) && io.internal_encoding
        io.internal_encoding
      elsif io.respond_to?(:external_encoding) && io.external_encoding
        io.external_encoding
      elsif io.respond_to?(:encoding)
        io.encoding
      else
        Encoding.default_external
      end
    end

    def build_candidates(evaluations)
      evaluations.filter_map do |config, result|
        next unless result.is_a?(Evaluation) && result.valid?
       Candidate.new(**config,
                     score: score(result),
                     evidence: evidence_for(result))
      end.sort_by.with_index do |candidate, index|
        row_separator_order = @row_separators.index(candidate.row_sep)
        quote_order = @quote_characters.index(candidate.quote_char)
        [-candidate.score,
         index,
         candidate.col_sep,
         row_separator_order,
         quote_order,
         candidate.quote_char.to_s]
      end
    end
 
    def rejections(evaluations)
      evaluations.filter_map do |config, result|
        if result.is_a?(Rejection)
          Rejection.new(**config, reason: result.reason, position: result.position)
        elsif !result.valid?
          Rejection.new(**config,
                        reason: result.error_reason,
                        position: result.error_position)
        end
      end
    end
 
    def score(result)
      widths = result.records
      record_count = widths.length
      return 0 if record_count.zero?
      score = 0
      if widths.uniq.length == 1
        score += record_count * 20
      else
        average = widths.sum / record_count.to_f
        variance = widths.sum { |width| (width - average) ** 2 } / record_count
        score += [100 - variance.to_i, 0].max
      end
      score += record_count * 25 if widths.all? { |width| width > 1 }
      score += result.row_ends * 2
      score += result.quoted_fields * 30
      score += result.embedded_col_seps * 25
      score += result.embedded_row_seps * 15
      score -= result.stray_row_separators * 20
      score -= result.raw_quotes if result.quoted_fields.zero?
      score
    end
 
    def evidence_for(result)
      {complete_records: result.records.length,
       field_counts: result.records,
       row_ends: result.row_ends,
       quoted_fields: result.quoted_fields,
       raw_quotes: result.raw_quotes,
       escaped_quotes: result.escaped_quotes,
       embedded_col_separators: result.embedded_col_seps,
       embedded_row_separators: result.embedded_row_seps,
       stray_row_separators: result.stray_row_separators,
       incomplete_reason: result.incomplete_reason,
       incomplete_position: result.incomplete_position}
    end
 
    def incomplete_reason(evaluations, candidates, rejected)
      return :empty_sample if @sample.empty?
      best = candidates.first
      return :no_valid_dialect if best.nil?
      damaged = rejected.any? { |candidate| candidate.reason == :unclosed_quote }
      return :damaged_unclosed_quote if @complete_input && damaged
      result = evaluation_for(evaluations, best)
      if result.records.length < (@complete_input ? 1 : 2)
        open_quote = evaluations.any? do |_, candidate|
          candidate.is_a?(Evaluation) &&
            candidate.valid? &&
            candidate.incomplete_reason == :unclosed_quote
        end
        return :unclosed_quote if open_quote
        result.incomplete_reason || :insufficient_complete_records
      end
    end
 
    def evaluation_for(evaluations, candidate)
      evaluations.assoc(candidate.to_h).last
    end
 
    def detect_ambiguities(candidates, incomplete_reason)
      return [] if incomplete_reason || candidates.empty?
      best_score = candidates.first.score
      tied = candidates.select { |candidate| candidate.score == best_score }
      [:col_sep, :row_sep, :quote_char].filter_map do |dimension|
        values = tied.map { |candidate| candidate.public_send(dimension) }.uniq
        next if values.length == 1
        if dimension == :quote_char && tied.first.evidence[:raw_quotes].zero?
          next
        end
        {dimension: dimension, values: values, reason: :equal_evidence}
      end
    end
 
    def evidence(evaluations, candidates)
      valid = evaluations.map(&:last).grep(Evaluation).select(&:valid?)
      {bytes_read: @sample.bytesize,
       complete_record_counts: valid.map { |result| result.records.length }.tally,
       valid_dialect_count: valid.length,
       best_score: candidates.first&.score}
    end
 
    class BufferedIO
      def initialize(io, sample, complete_input, encoding)
        @io = io
        @encoding = encoding
        @sources = []
        @sources << StringIO.new(sample) unless sample.empty?
        @sources << io unless complete_input
        @pending = +""
        @final_buffer_returned = false
      end
 
      def gets(separator = $/, limit = nil)
        if separator.nil? && limit
          return read(limit)
        end
 
        until @sources.empty?
          line = buffered_line(separator, limit, target_encoding)
          return line if line
 
          source = @sources.first
          chunk = source.read(8192)
          if chunk
            @pending << chunk
            next
          end
          @sources.shift
        end
        if @pending.empty? || @final_buffer_returned
          nil
        else
          @final_buffer_returned = true
          value = @pending.dup
          @pending = +""
          value
        end
      end
 
      def read(length = nil)
        until length.nil? || @sources.empty?
          source = @sources.first
          chunk = source.read(length)
          @pending << chunk if chunk
          @sources.shift if source.respond_to?(:eof?) && source.eof?
          break if chunk.nil? || @pending.bytesize >= length
        end
        return @pending.dup unless length
        consume_pending([length, @pending.bytesize].min) unless @pending.empty?
      end
 
      def eof?
        !@pending.empty? ||
          @sources.any? do |source|
            !source.respond_to?(:eof?) || !source.eof?
          end
      end
 
      def internal_encoding
        @io.internal_encoding if @io.respond_to?(:internal_encoding)
      end
 
      def external_encoding
        if @io.respond_to?(:external_encoding)
          @io.external_encoding
        elsif @io.respond_to?(:encoding)
          @io.encoding
        end
      end
 
      def target_encoding
        @encoding || internal_encoding || external_encoding ||
          Encoding::ASCII_8BIT
      end

      private
      def buffered_line(separator, limit, encoding)
        return nil unless separator
        index = @pending.index(separator)
        end_position = index ? index + separator.bytesize : nil
        if end_position && (limit.nil? || end_position <= limit) &&
           valid_encoding?
          force_encoding(consume_pending(end_position), encoding)
        elsif limit && @pending.bytesize >= limit &&
              valid_encoding?
          force_encoding(consume_pending(@pending.bytesize), encoding)
        else
          nil
        end
      end
 
      def valid_encoding?
        @pending.dup.force_encoding(target_encoding).valid_encoding?
      end
 
      def force_encoding(string, encoding)
        string.force_encoding(encoding) if string.valid_encoding?
        string
      end

      def consume_pending(length)
        value = @pending.byteslice(0, length)&.dup
        remaining_length = @pending.bytesize - length
        remainder = remaining_length.zero? ? nil : @pending.byteslice(length,
                                                                       remaining_length)
        @pending = remainder.nil? ? +"" : remainder
        value
      end
    end
  end
end
