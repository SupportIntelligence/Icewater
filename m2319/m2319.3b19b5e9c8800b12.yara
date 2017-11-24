
rule m2319_3b19b5e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b19b5e9c8800b12"
     cluster="m2319.3b19b5e9c8800b12"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['1b970ebf989c2529c5a074790f1d1806','32cd42f7e84df7539469b4e36f3bec44','ed0708e29289ba822883b7dca72eafbf']"

   strings:
      $hex_string = { 38353231393930363139375c783236636f6c6f72735c78336443677430636d467563334268636d56756442494c64484a68626e4e7759584a6c626e516142794d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
