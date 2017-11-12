
rule m400_29159de9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m400.29159de9c8800b32"
     cluster="m400.29159de9c8800b32"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['42d62cad5768e332e15331fced113436','97d7154334ee91ea7606cb93ed4b1dfb','f112847931dc215634bfd1b046d7a625']"

   strings:
      $hex_string = { 9a9ce783ea2a5800de708930728a51a6066fe7d79b941a8d6588a6458722040613c8c437cb2a04007085859e89860d6d0623c63950601ae365bfbecb888170f0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
