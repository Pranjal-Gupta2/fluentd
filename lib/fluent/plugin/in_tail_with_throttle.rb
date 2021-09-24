#
# Fluentd
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
require 'fluent/plugin/input'
require 'fluent/config/error'
require 'fluent/plugin/in_tail'

module Fluent::Plugin
  class ThrottleInput < Fluent::Plugin::TailInput
    Fluent::Plugin.register_input('tail_with_throttle', self)
    
    DEFAULT_GROUP = /./

    def initialize
      super
      # Map rules with GroupWatcher objects
      @group_watchers = {}
      @sorted_path = nil
    end

    config_section :group_by, param_name: :group, required: true, multi: false do
      config_argument :type, :enum, list: [:metadata, :metrics], default: :metadata
      desc 'Regex for extracting group\'s metadata'
      config_param :pattern, 
                    :regexp, 
                    default: /var\/log\/containers\/(?<pod>[a-z0-9]([-a-z0-9]*[a-z0-9])?(\/[a-z0-9]([-a-z0-9]*[a-z0-9])?)*)_(?<namespace>[^_]+)_(?<container>.+)-(?<docker_id>[a-z0-9]{64})\.log$/
      desc 'Period of time in which the group_line_limit is applied'
      config_param :rate_period_s, :integer, default: 60

      config_section :metadata_rule, multi: true, required: false do
        desc 'Namespace key'
        config_param :namespace, :array, value_type: :string, default: [DEFAULT_GROUP]
        desc 'Podname key'
        config_param :pod, :array, value_type: :string, default: [DEFAULT_GROUP]
        desc 'Maximum number of log lines allowed per group over a period of rate_period_s'
        config_param :limit, :integer, default: -1
      end

      config_section :metric_rule, multi: true, required: false do
        desc "Metric used for Grouping"
        config_param :metric, :enum, list: [:TopN], default: :TopN
        desc "Parameter used by metric (if any)"
        config_param :param, :integer, default: 5
        desc 'Maximum number of log lines allowed per group over a period of rate_period_s'
        config_param :limit, :integer, default: -1        
      end
    end

    def configure(conf)
      super
      ## Ensuring correct time period syntax
      raise "rate_period_s > 0" unless @group.rate_period_s > 0
      unless @group.metric_rule.nil?
        @group.metric_rule.each { |rule|
          raise "Metric Group Limit >= -1" unless rule.limit >= -1
        }
      end
      unless @group.metadata_rule.nil?
        @group.metadata_rule.each { |rule| 
          raise "Metadata Group Limit >= -1" unless rule.limit >= -1
        }
      end

      ## Make sure that rules are ordered
      ## Unordered rules can cause unexpected grouping
      case @group.type
      when :metadata
        @group.metadata_rule.each { |rule|
          num_groups = rule.namespace.size * rule.pod.size
          
          rule.namespace.each { |namespace| 
            namespace = /#{Regexp.quote(namespace)}/ unless namespace.eql?(DEFAULT_GROUP)
            @group_watchers[namespace] ||= {}
  
            rule.pod.each { |pod|
              pod = /#{Regexp.quote(pod)}/ unless pod.eql?(DEFAULT_GROUP)
            
              @group_watchers[namespace][pod] = GroupWatcher.new(@group.rate_period_s, rule.limit/num_groups)
            }
  
            @group_watchers[namespace][DEFAULT_GROUP] ||= GroupWatcher.new(@group.rate_period_s)
          }
        }

        if @group_watchers.dig(DEFAULT_GROUP, DEFAULT_GROUP).nil?
          @group_watchers[DEFAULT_GROUP] ||= {}
          @group_watchers[DEFAULT_GROUP][DEFAULT_GROUP] = GroupWatcher.new(@group.rate_period_s)
        end
  
        @group_watchers.each { |key, hash| 
          next if hash[DEFAULT_GROUP].limit == -1
          hash[DEFAULT_GROUP].limit -= hash.select{ |key, value| key != DEFAULT_GROUP}.values.reduce(0) { |sum, obj| sum + obj.limit }
          raise "#{key}.\* limit < 0" unless hash[DEFAULT_GROUP].limit >= 0
        }
  
        @group_watchers[DEFAULT_GROUP].each { |key, value| 
          next if key == DEFAULT_GROUP || value.limit == -1
          l = @group_watchers.select{ |key1, value1| key1 != DEFAULT_GROUP }
          l = l.values.select{ |hash| hash.select{ |key1, value1| key1 == key}.size > 0 }
          @group_watchers[DEFAULT_GROUP][key].limit -= l.reduce(0) { |sum, obj| sum + obj[key].limit}
          raise "\*.#{key} limit < 0" unless @group_watchers[DEFAULT_GROUP][key].limit >= 0
        }

      when :metrics
        @group.metric_rule.each { |rule| 
          case rule.metric
          when :TopN
            @group_watchers[:TopN] = TopNGroupWatcher.new(@group.rate_period_s, rule.limit, rule.param)
            @group_watchers[DEFAULT_GROUP] = TopNGroupWatcher.new
          else
            raise "Group Metric Type: #{rule.metric} not found"
          end
        }
      end
    end

    def find_group_from_metadata(path)
      def find_group(namespace, pod)
        namespace_key = @group_watchers.keys.find { |regexp| namespace.match?(regexp) && regexp != DEFAULT_GROUP }
        namespace_key ||= DEFAULT_GROUP

        pod_key = @group_watchers[namespace_key].keys.find { |regexp| pod.match?(regexp) && regexp != DEFAULT_GROUP }
        pod_key ||= DEFAULT_GROUP

        @group_watchers[namespace_key][pod_key]
      end
  
      begin
        metadata = @group.pattern.match(path)
        group_watcher = find_group(metadata['namespace'], metadata['pod'])
      rescue => e
        $log.warn "Cannot find group from metadata, Adding file in the default group"
        group_watcher = @group_watchers[DEFAULT_GROUP][DEFAULT_GROUP] 
      end

      group_watcher
    end

    def refresh_watchers
      @sorted_path = sort_files_by_log_generation_rate
      super

      case @group.type
      # when :metadata
        # metadata rule don't need update
      when :metrics
        ## Get TopN Files
        ## TopN Existence files - TOPN Group
        ## Added + remaining files - Default Group
        ## Also update previous TailWatcher's GroupWatcher object
        group_watcher = @group_watchers[:TopN]
        group_watcher.current_paths = []

        n = group_watcher.num_container

        @sorted_path.first(n).each { |_, tw| 
          tw.group_watcher = group_watcher
          group_watcher.current_paths << tw.path
        }

        group_watcher = @group_watchers[DEFAULT_GROUP]
        group_watcher.current_paths = []
  
        @sorted_path.last(@sorted_path.size - n).each { |_, tw| 
          tw.group_watcher = group_watcher
          group_watcher.current_paths << tw.path
        } unless @sorted_path.size - n < 0
      end

    end

    def sort_files_by_log_generation_rate
      paths_with_log_collected_info = []

      @tails.each_value { |tw|
        begin
          stat = Fluent::FileWrapper.stat(tw.path)
        rescue Errno::ENOENT, Errno::EACCES
          # moved or deleted
          stat = nil
        end 

        old_pos = tw.instance_variable_get(:@_old_pos) || 0.0
        old_inode = tw.instance_variable_get(:@_old_inode)
        if !stat.nil?
          tw.instance_variable_set(:@_old_pos, stat.size)
          tw.instance_variable_set(:@_old_inode, stat.ino)

          if stat.ino == old_inode && stat.size >= old_pos
            paths_with_log_collected_info << [(stat.size - old_pos)/@refresh_interval, tw]
          else
            paths_with_log_collected_info << [stat.size/@refresh_interval, tw]
          end
        else 
          puts "Stat Object nil for #{tw.path}"
        end
      }

      paths_with_log_collected_info.sort! { |list_a, list_b| -list_a[0] <=> -list_b[0] }
      paths_with_log_collected_info 

    end

    def stop_watchers(targets_info, immediate: false, unwatched: false, remove_watcher: true)
      case @group.type
      when :metadata
        targets_info.each_value { |target_info|
          group_watcher = find_group_from_metadata(target_info.path)
          group_watcher.current_paths.delete(target_info.path)
        }
      end
      super
    end

    def setup_watcher(target_info, pe)
      case @group.type
      when :metadata 
        group_watcher = find_group_from_metadata(target_info.path)
      when :metrics
        n = @group_watchers[:TopN].num_container
        if @sorted_path.first(n).include? target_info.path 
          group_watcher = @group_watchers[:TopN] 
        else 
          group_watcher = @group_watchers[DEFAULT_GROUP]
        end
      end

      tw = super
      group_watcher.current_paths << tw.path unless group_watcher.current_paths.include? tw.path
      tw.group_watcher = group_watcher

      tw
    end


    class GroupWatcher
      attr_accessor :current_paths, :limit, :number_lines_read, :start_reading_time, :rate_period_s
      def initialize(rate_period_s = 60, limit = -1)
        @current_paths = []
        @rate_period_s = rate_period_s
        @limit = limit
        @number_lines_read = 0
        @start_reading_time = nil
      end

      def limit_lines_reached?
        return true if @limit == 0
        return false if @limit < 0
        return false if @number_lines_read < @limit/@current_paths.size

        @start_reading_time ||= Fluent::Clock.now
        time_spent_reading = Fluent::Clock.now - @start_reading_time

        if time_spent_reading < @rate_period_s
          # Exceeds limit
          true
        else
          # Does not exceed limit
          @start_reading_time = nil
          @number_lines_read = 0
          false
        end
      end

      def to_s
        super + " current_paths: #{@current_paths} rate_period_s: #{@rate_period_s} limit: #{@limit}"
      end
    end


    class TopNGroupWatcher < GroupWatcher
      attr_accessor :num_container
      def initialize(rate_period_s = 60, limit = 0, num_container = -1)
        super(rate_period_s, limit)
        @num_container = num_container
      end

      def to_s
        super + " num_container: #{num_container}"
      end
    end


    class Fluent::Plugin::TailInput::TailWatcher
      attr_accessor :group_watcher

      def group_watcher=(group_watcher)
        @group_watcher = group_watcher
      end


      class Fluent::Plugin::TailInput::TailWatcher::IOHandler
        alias_method :orig_handle_notify, :handle_notify

        def group_watcher
          @watcher.group_watcher
        end

        def rate_limit_handle_notify
          return if group_watcher.limit_lines_reached?

          with_io do |io|
            begin
              read_more = false

              if !io.nil? && @lines.empty?
                begin
                  while true
                    group_watcher.start_reading_time ||= Fluent::Clock.now
                    data = io.readpartial(BYTES_TO_READ, @iobuf)
                    @eof = false
                    @fifo << data
                    group_watcher.number_lines_read -= @lines.size
                    @fifo.read_lines(@lines)
                    group_watcher.number_lines_read += @lines.size

                    if group_watcher.limit_lines_reached? || should_shutdown_now?
                      # Just get out from tailing loop.
                      read_more = false
                      break
                    elsif @lines.size >= @read_lines_limit
                      # not to use too much memory in case the file is very large
                      read_more = true
                      break
                    end
                  end
                rescue EOFError
                  @eof = true
                end
              end
              puts "Reading: #{@watcher.path} #{@watcher.ino} EOF: #{@eof} Lines: #{group_watcher.number_lines_read}"

              if !read_more
                # reset counter for files in same group
                group_watcher.start_reading_time = nil
                group_watcher.number_lines_read = 0
              end

              unless @lines.empty?
                if @receive_lines.call(@lines, @watcher)
                  @watcher.pe.update_pos(io.pos - @fifo.bytesize)
                  @lines.clear
                else
                  read_more = false
                end
              end
            end while read_more
          end
        end

        def handle_notify
          if @watcher.group_watcher.nil?
            orig_handle_notify
          else
            rate_limit_handle_notify
          end
        end
      end      
    end
  end
end
