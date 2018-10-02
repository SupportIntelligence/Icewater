
rule k2319_103296b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.103296b9c8800b12"
     cluster="k2319.103296b9c8800b12"
     cluster_size="43"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['0c4ac4956c7b7ecfb6f5002d3368584b5eabff15','30387234c385b3963ea83a92bf6772d2c4cf1aab','320831c7249353cc24811cae49b21a7fed0df900']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.103296b9c8800b12"

   strings:
      $hex_string = { 3a2835322e393045312c30783337292929627265616b7d3b7661722066327333793d7b27633379273a66756e6374696f6e28562c4a297b72657475726e20567c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
