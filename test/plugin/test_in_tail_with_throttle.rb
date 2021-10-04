require_relative '../helper'
require_relative './test_in_tail'
require 'fluent/test'
require 'fluent/test/helpers'
require 'fluent/test/driver/input'
require 'fluent/plugin/in_tail_with_throttle'

class ThrottleInputTest < TailInputTest

  def create_group_directive(pattern, rate_period, *rules)
    config_element("", "", {}, [
      config_element("group", "", {
        "pattern" => pattern,
        "rate_period" => rate_period
      }, rules)
    ])
  end

  def create_rule_directive(namespace = [], podname = [], limit)
    params = {        
      "limit" => limit,
    }
    params["namespace"] = namespace.join(', ') if namespace.size > 0
    params["pod"] = podname.join(', ') if podname.size > 0
    config_element("rule", "", params)
  end

  def create_path_element(path)
    config_element("source", "", { "path" => "#{TMP_DIR}/#{path}" })
  end

  def create_driver(conf, add_path = true)
    conf = add_path ? conf + create_path_element("tail.txt") : conf
    Fluent::Test::Driver::Input.new(Fluent::Plugin::ThrottleInput).configure(conf)
  end

  CONFG = config_element("source", "", {
    "@type" => "tail_with_throttle",
    "tag" => "t1",
    "pos_file" => "#{TMP_DIR}/tail.pos", 
    "refresh_interval" => "0.5s",
    "rotate_wait" => "0.5s",
  }, [
    config_element("parse", "", { 
      "@type" => "/(?<message>.*)/" })
    ]
  )
  PATTERN = "/#{TMP_DIR}\/(?<pod>[a-z0-9]([-a-z0-9]*[a-z0-9])?(\/[a-z0-9]([-a-z0-9]*[a-z0-9])?)*)_(?<namespace>[^_]+)_(?<container>.+)-(?<docker_id>[a-z0-9]{6})\.log$/"
  READ_FROM_HEAD = config_element("source", "", { "read_from_head" => "true" })

  sub_test_case "#configuration" do
    
    test "<group> required" do
      assert_raise(Fluent::ConfigError) do
        d = create_driver(CONFG)
      end
    end

    test "<rule> required" do
      conf = CONFG + create_group_directive('.', '1m')
      assert_raise(Fluent::ConfigError) do 
        d = create_driver(conf)
      end
    end

    test "valid configuration" do
      rule1 = create_rule_directive(['namespace-a'], ['pod-b','pod-c'], 100)
      rule2 = create_rule_directive(['namespace-d', 'pod-e'], ['f'], 50)
      rule3 = create_rule_directive([], ['pod-g'], -1)
      rule4 = create_rule_directive(['pod-h'], [], 0)

      conf = CONFG + create_group_directive('.', '1m', rule1, rule2, rule3, rule4)
      assert_nothing_raised do 
        d = create_driver(conf)
      end
    end

    test "limit should be greater than DEFAULT_LIMIT (-1)" do 
      rule1 = create_rule_directive(['namespace-a'], ['pod-b','pod-c'], -100)
      rule2 = create_rule_directive(['namespace-d', 'namespace-e'], ['pod-f'], 50)
      conf = CONFG + create_group_directive('.', '1m', rule1, rule2)
      assert_raise(RuntimeError) do 
        d = create_driver(conf)
      end   
    end

  end
  
  sub_test_case "group rules line limit resolution" do

    test "invalid intra group" do  
      ## In the first rule, namespace-a, pod-b & namespace-a, pod-c allow 50 lines each.
      ## In the second rule, namespace-a collectively allows 40 lines which 
      ## is contradictory to Rule 1. Hence, this configuration will issue a RuntimeError
      ## while parsing the configuration
      
      ## This configuration can be rectified by allowing a limit greater than 100 for Rule2.
      ## OR
      ## This configuration can be rectified by allowing a limit less then 40 for Rule 1.

      rule1 = create_rule_directive(['namespace-a'], ['pod-b', 'pod-c'], 100)
      rule2 = create_rule_directive(['namespace-a'], [], 40)
      conf = CONFG + create_group_directive('.', '1m', rule1, rule2)

      assert_raise(RuntimeError) do
        d = create_driver(conf)
      end

    end

    test "invalid inter group" do
      ## First rule dictates that namespace-a, pod-b will allow a total 100 lines
      ## from that group. 
      ## However, second rule dictates that irrespective of namespace, 
      ## all log files generated from pod-b will collectively allow only 50 lines. 

      ## This configuration can be rectified by allowing a limit greater than 100 for Rule 2
      ## OR
      ## This configuration can be rectified by allowing a limit less than 50 for Rule 1

      rule1 = create_rule_directive(['namespace-a'], ['pod-b'], 100)
      rule2 = create_rule_directive([], ['pod-b'], 50)
      conf = CONFG + create_group_directive('.', '1m', rule1, rule2)

      assert_raise(RuntimeError) do
        d = create_driver(conf)
      end

    end

    test "valid" do
      rule1 = create_rule_directive(['namespace-a'], ['pod-b', 'pod-c'], 50)
      rule2 = create_rule_directive([], ['pod-b', 'pod-c'], 200)
      rule3 = create_rule_directive(['namespace-a'], [], 100)
  
      conf = CONFG + create_group_directive('.', '1m', rule1, rule2, rule3)
      assert_nothing_raised do
        d = create_driver(conf)

        assert_equal 25, d.instance.group_watchers[/namespace\-a/][/pod\-b/].limit
        assert_equal 25, d.instance.group_watchers[/namespace\-a/][/pod\-c/].limit
        assert_equal 50, d.instance.group_watchers[/namespace\-a/][/./].limit
        assert_equal 75, d.instance.group_watchers[/./][/pod\-b/].limit
        assert_equal 75, d.instance.group_watchers[/./][/pod\-c/].limit
        assert_equal -1, d.instance.group_watchers[/./][/./].limit
      end
    end

  end

  sub_test_case "files should be placed in groups" do
    test "invalid regex pattern places files in default group" do
      rule1 = create_rule_directive([], [], 100) ## limits default groups
      conf = CONFG + create_group_directive('.', '1m', rule1) + create_path_element("test*.txt")

      d = create_driver(conf, false)
      File.open("#{TMP_DIR}/test1.txt", 'w')
      File.open("#{TMP_DIR}/test2.txt", 'w')
      File.open("#{TMP_DIR}/test3.txt", 'w')

      d.run do
        ## checking default group_watcher's paths
        assert_equal 3, d.instance.group_watchers[/./][/./].size
        assert_true d.instance.group_watchers[/./][/./].include? File.join(TMP_DIR, 'test1.txt')
        assert_true d.instance.group_watchers[/./][/./].include? File.join(TMP_DIR, 'test2.txt')
        assert_true d.instance.group_watchers[/./][/./].include? File.join(TMP_DIR, 'test3.txt')
      end
    end
    
    test "valid regex pattern places file in their respective groups" do
      rule1 = create_rule_directive(['test-namespace1'], ['test-pod1'], 100)
      rule2 = create_rule_directive(['test-namespace1'], [], 200)
      rule3 = create_rule_directive([], ['test-pod2'], 100)
      rule4 = create_rule_directive([], [], 100)

      path_element = create_path_element("test-pod*.log")

      conf = CONFG + create_group_directive(PATTERN, '1m', rule1, rule2, rule3, rule4) + path_element
      d = create_driver(conf, false)

      File.open("#{TMP_DIR}/test-pod1_test-namespace1_test-container-15fabq.log", 'w')
      File.open("#{TMP_DIR}/test-pod3_test-namespace1_test-container-15fabq.log", 'w')
      File.open("#{TMP_DIR}/test-pod2_test-namespace2_test-container-15fabq.log", 'w')
      File.open("#{TMP_DIR}/test-pod4_test-namespace3_test-container-15fabq.log", 'w')

      d.run do
        assert_true d.instance.group_watchers[/test\-namespace1/][/test\-pod1/].include? File.join(TMP_DIR, "test-pod1_test-namespace1_test-container-15fabq.log")
        assert_true d.instance.group_watchers[/test\-namespace1/][/./].include? File.join(TMP_DIR, "test-pod3_test-namespace1_test-container-15fabq.log")
        assert_true d.instance.group_watchers[/./][/test\-pod2/].include? File.join(TMP_DIR, "test-pod2_test-namespace2_test-container-15fabq.log")
        assert_true d.instance.group_watchers[/./][/./].include? File.join(TMP_DIR, "test-pod4_test-namespace3_test-container-15fabq.log")
      end
    end
  
  end

  sub_test_case "throttling logs at in_tail level" do

    data("file test1.log no limit 5120 text: msg" => ["test1.log", 5120, "msg"],
         "file test2.log no limit 1024 text: test" => ["test2.log", 1024, "test"])
    def test_lines_collected_with_no_throttling(data)
      file, num_lines, msg = data
      rule = create_rule_directive([], [], -1)
      path_element = create_path_element(file)

      conf = CONFG + create_group_directive('.', '10s', rule) + path_element + READ_FROM_HEAD
      File.open("#{TMP_DIR}/#{file}", 'wb') do |f|
        num_lines.times do 
          f.puts "#{msg}\n"
        end
      end


      d = create_driver(conf, false)
      d.run do
        start_time = Time.now

        assert_true Time.now - start_time < 10
        assert_equal num_lines, d.record_count
        assert_equal({ "message" => msg }, d.events[0][2])

        prev_count = d.record_count
        ## waiting for atleast 12 seconds to avoid any sync errors between plugin and test driver
        sleep(1) until Time.now - start_time > 12
        ## after waiting for 10 secs, limit will reset 
        ## Plugin will start reading but it will encounter EOF Error 
        ## since no logs are left to be read
        ## Hence, d.record_count = prev_count
        assert_equal 0, d.record_count - prev_count
      end
    end
    
    test "lines collected with throttling" do
      file = "podname1_namespace12_container-123456.log"
      limit = 1000
      rate_period = '10s'
      num_lines = 3000
      msg = "a"*8190 # Total size = 8190 bytes + 2 (\n) bytes

      rule = create_rule_directive(['namespace'], ['podname'], limit)
      path_element = create_path_element(file)
      conf = CONFG + create_group_directive(PATTERN, rate_period, rule) + path_element + READ_FROM_HEAD

      d = create_driver(conf, false)

      File.open("#{TMP_DIR}/#{file}", 'wb') do |f|
        num_lines.times do 
          f.puts msg
        end
      end

      d.run do
        start_time = Time.now
        prev_count = 0

        3.times do
          assert_true Time.now - start_time < 10
          ## Check record_count after 10s to check lines reads
          assert_equal limit, d.record_count - prev_count
          prev_count = d.record_count 
          ## sleep until rate_period seconds are over so that 
          ## Plugin can read lines again
          sleep(1) until Time.now - start_time > 12 
          ## waiting for atleast 12 seconds to avoid any sync errors between plugin and test driver
          start_time = Time.now
        end
        ## When all the lines are read and rate_period seconds are over
        ## limit will reset and since there are no more logs to be read,
        ## number_lines_read will be 0
        assert_equal 0, d.instance.group_watchers[/namespace/][/podname/].current_paths["#{TMP_DIR}/#{file}"].number_lines_read
      end


    end
  end

end

