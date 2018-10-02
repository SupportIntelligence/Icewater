
rule j2319_2917ac4cea200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.2917ac4cea200912"
     cluster="j2319.2917ac4cea200912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script sload boqcx"
     md5_hashes="['0fb4e5b6c39d8cc5f8f0431f677ac5071b730869','fe028ff1a73ed2e53bceba50d6ff97fe2fe2aedc','6f4ea5f69f629d00a88fb5f8e76231111d984a42']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.2917ac4cea200912"

   strings:
      $hex_string = { 365d2b70796c5b345d2b63736277792e736d647d66756e6374696f6e20666a7062286e297b72657475726e206b657a6c5b325d2b64756168775b325d2b71746d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
