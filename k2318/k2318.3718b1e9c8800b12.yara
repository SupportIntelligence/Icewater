
rule k2318_3718b1e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3718b1e9c8800b12"
     cluster="k2318.3718b1e9c8800b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['5523047cb3a5376a2751165b5c99c16012d4b60e','6c939351f907d887e39cb66500b5e8c3572ee2e7','aa0bbb0fbce87de5dfe4c01b769fe1dc9a620ad5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3718b1e9c8800b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
