#!/usr/bin/env ruby
# frozen_string_literal: true

Dir[File.join(__dir__, 'test_*.rb')].sort.each { |file| require file }
