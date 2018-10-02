
rule k2319_381687adc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.381687adc6220b12"
     cluster="k2319.381687adc6220b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['cd9e433e8afc823446d228babf3082fb4f492ab2','8928b61d7ea25d9aa5e921d7b73278ed6bcb40d4','05ad50b7f6541fb623abe0a74f7cc5cfa386847c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.381687adc6220b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20755b525d3b7d76617220533d28283078382c31312e293c3d2831332e383845322c37352e293f28362e2c3078636339653264 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
