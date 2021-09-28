require_relative '../helper'
require 'fluent/test'
require 'fluent/test/helpers'
require 'fluent/test/driver/input'
require 'fluent/plugin/in_tail_with_throttle'

class ThrottleInputTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
  end

  CONFG = config_element("source", "", {
    "@type" => "tail_with_throttle",
    "tag" => "t1",
    "pos_file" => "a_pos.txt", 
    "refresh_interval" => "1s",
    "rotate_wait" => "2s",
  }, [
    config_element("parse", "", {
      "@type" => "regexp",
      "expression" => "/^\\[(?<time>[^\\]]*)\\](?<data>.*)$/",
      "time_key" => "time",
      "time_format" => "%Y-%m-%d %H:%M:%S,%N",
      "keep_time_key" => "true",
    })
  ])

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

  def create_driver(conf, add_path = true)
    conf = add_path ? conf + config_element("source", "", {"path" => "temp.txt"}) : conf
    Fluent::Test::Driver::Input.new(Fluent::Plugin::ThrottleInput).configure(conf)
  end

  def create_target_info(path)
    Fluent::Plugin::TailInput::TargetInfo.new(path, Fluent::FileWrapper.stat(path).ino)
  end

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
      rule1 = create_rule_directive(['a'], ['b','c'], 100)
      rule2 = create_rule_directive(['d', 'e'], ['f'], 50)
      rule3 = create_rule_directive([], ['g'], -1)
      rule4 = create_rule_directive(['h'], [], 0)

      conf = CONFG + create_group_directive('.', '1m', rule1, rule2, rule3, rule4)
      assert_nothing_raised do 
        d = create_driver(conf)
      end
    end

    test "limit should be greater than DEFAULT_LIMIT (-1)" do 
      rule1 = create_rule_directive(['a'], ['b','c'], -100)
      rule2 = create_rule_directive(['d', 'e'], ['f'], 50)
      conf = CONFG + create_group_directive('.', '1m', rule1, rule2)
      assert_raise(RuntimeError) do 
        d = create_driver(conf)
      end   
    end

  end
  
  sub_test_case "group rules line limit resolution" do

    test "invalid intra group" do 
      rule1 = create_rule_directive(['a'], ['b', 'c'], 100)
      rule2 = create_rule_directive(['a'], [], 40)
      conf = CONFG + create_group_directive('.', '1m', rule1, rule2)

      assert_raise(RuntimeError) do
        d = create_driver(conf)
      end

    end

    test "invalid inter group" do
      rule1 = create_rule_directive(['a'], ['b'], 100)
      rule2 = create_rule_directive([], ['b'], 50)
      conf = CONFG + create_group_directive('.', '1m', rule1, rule2)

      assert_raise(RuntimeError) do
        d = create_driver(conf)
      end

    end

    test "valid" do
      rule1 = create_rule_directive(['a'], ['b', 'c'], 50)
      rule2 = create_rule_directive([], ['b', 'c'], 200)
      rule3 = create_rule_directive(['a'], [], 100)
  
      conf = CONFG + create_group_directive('.', '1m', rule1, rule2, rule3)
      assert_nothing_raised do
        d = create_driver(conf)

        assert_equal 25, d.instance.group_watchers[/a/][/b/].limit
        assert_equal 25, d.instance.group_watchers[/a/][/c/].limit
        assert_equal 50, d.instance.group_watchers[/a/][/./].limit
        assert_equal 75, d.instance.group_watchers[/./][/b/].limit
        assert_equal 75, d.instance.group_watchers[/./][/c/].limit
        assert_equal -1, d.instance.group_watchers[/./][/./].limit
      end
    end

  end

  sub_test_case "files should be placed in groups" do
    test "invalid regex pattern places files in default group" do
      rule1 = create_rule_directive([], [], 100)
      conf = CONFG + create_group_directive('.', '1m', rule1) + config_element("source", "", {"path" => "test*.txt"})

      d = create_driver(conf, false)
      File.new('test1.txt', 'w')
      File.new('test2.txt', 'w')
      File.new('test3.txt', 'w')

      d.run do
        assert_equal 3, d.instance.group_watchers[/./][/./].size
        assert_true d.instance.group_watchers[/./][/./].include? 'test1.txt'
        assert_true d.instance.group_watchers[/./][/./].include? 'test2.txt'
        assert_true d.instance.group_watchers[/./][/./].include? 'test3.txt'
      end
    end
    
    test "valid regex pattern places file in their respective groups" do
      rule1 = create_rule_directive(['test-namespace1'], ['test-pod1'], 100)
      rule2 = create_rule_directive(['test-namespace1'], [], 200)
      rule3 = create_rule_directive([], ['test-pod2'], 100)
      rule4 = create_rule_directive([], [], 100)

      path_element = config_element("source", "", {"path" => "test-pod*.log"})
      pattern = "/(?<pod>[a-z0-9]([-a-z0-9]*[a-z0-9])?(\/[a-z0-9]([-a-z0-9]*[a-z0-9])?)*)_(?<namespace>[^_]+)_(?<container>.+)-(?<docker_id>[a-z0-9]{6})\.log$/"

      conf = CONFG + create_group_directive(pattern, '1m', rule1, rule2, rule3, rule4) + path_element
      d = create_driver(conf, false)

      File.new("test-pod1_test-namespace1_test-container-15fabq.log", 'w')
      File.new("test-pod3_test-namespace1_test-container-15fabq.log", 'w')
      File.new("test-pod2_test-namespace2_test-container-15fabq.log", 'w')
      File.new("test-pod4_test-namespace3_test-container-15fabq.log", 'w')


      d.run do
        assert_true d.instance.group_watchers[/test\-namespace1/][/test\-pod1/].include? "test-pod1_test-namespace1_test-container-15fabq.log"
        assert_true d.instance.group_watchers[/test\-namespace1/][/./].include? "test-pod3_test-namespace1_test-container-15fabq.log"
        assert_true d.instance.group_watchers[/./][/test\-pod2/].include? "test-pod2_test-namespace2_test-container-15fabq.log"
        assert_true d.instance.group_watchers[/./][/./].include? "test-pod4_test-namespace3_test-container-15fabq.log"
      end
    end
  
  end

end

