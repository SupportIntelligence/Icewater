
rule k2319_180c96b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.180c96b9caa00b12"
     cluster="k2319.180c96b9caa00b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['9d99b2f6404c074657601bf506b00d6beda28b50','01a6f13f1e6306f54e7c7e014c3c03150b86ac27','cb97ea738162bb76d6bd4de805a14a17688b5274']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.180c96b9caa00b12"

   strings:
      $hex_string = { 2e353945323f28312e30373645332c313139293a2832312c3930292929627265616b7d3b7661722073325a31593d7b27493559273a66756e6374696f6e284a2c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
