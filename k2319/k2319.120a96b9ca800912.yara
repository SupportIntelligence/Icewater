
rule k2319_120a96b9ca800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.120a96b9ca800912"
     cluster="k2319.120a96b9ca800912"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4e9191d8e69adbce6aa1ef49b7f262f4132c8837','83f18598cf6d48abe4e313022fe779fe028d1ddb','4befdff1b36c33497b59856f5180ba05338af999']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.120a96b9ca800912"

   strings:
      $hex_string = { 3f28312e30333645332c313139293a2839362e3545312c30783141292929627265616b7d3b76617220793559376c3d7b2751396c273a66756e6374696f6e286a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
