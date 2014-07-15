module Net # :nodoc:
  module DNS
    class RR
      
      #------------------------------------------------------------
      # RR type SRV
      #------------------------------------------------------------
      class SRV < RR
        
        attr_reader :priority, :weight, :port, :host

        SRV_REGEXP = Regexp.new("(\\d) (\\d) (\\d+) (\\w+)", Regexp::IGNORECASE)
        
        private
        
        # def build_pack
        #   str = ""
        # end

        def subclass_new_from_string(rrstring)
          if rrstring.class == String
            unless rrstring =~ SRV_REGEXP
              raise ArgumentError,
              "Format error for RR string (maybe CLASS and TYPE not valid?)"
            end
            @priority = $1.to_i
            @weight = $2.to_i
            @port = $3.to_i
            @host = $4
          end
        end
        
        def subclass_new_from_binary(data,offset)
          off_end = offset + @rdlength
          @priority, @weight, @port = data.unpack("@#{offset} n n n")
          offset+=6

          @host=[]
          while offset < off_end
            len = data.unpack("@#{offset} C")[0]
            offset += 1
            str = data[offset..offset+len-1]
            offset += len
            @host << str
          end
          @host=@host.join(".")
          offset
        end
        
        private
        
          def set_type
            @type = Net::DNS::RR::Types.new("SRV")
          end

          def build_pack
            puts "Host: #{@host}"
            @srvdata=[@priority.to_i, @weight.to_i, @port.to_i, @host.length].pack(" n n n C")+@host#.scan(/./).map(&:to_i).pack("C#{@host.length}")#+pack_name(@host)
            @rdlength = @srvdata.size
          end

          def get_data
            @srvdata
          end
        
      end
    end
        
  end
end
