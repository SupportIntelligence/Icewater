
rule k2319_39473ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39473ec1c8000b12"
     cluster="k2319.39473ec1c8000b12"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script multiplug diplugem"
     md5_hashes="['22d381876db82cc0ba47d224308baceff1c59625','874f38ff731dd739704b7105f58637baf4f46b71','2ec93788111a94aecdcf2c488201223ce4d2d8c5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39473ec1c8000b12"

   strings:
      $hex_string = { 7d2c276d3730273a66756e6374696f6e28612c62297b72657475726e20613e623b7d7d3b6368726f6d655b2857337836302e4d35362b57337836302e5938362b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
