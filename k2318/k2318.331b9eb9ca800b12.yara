
rule k2318_331b9eb9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.331b9eb9ca800b12"
     cluster="k2318.331b9eb9ca800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['56f65289e119fa1851f896b9b7892ace62596349','c95b7a656ac1007701707a2a64063409a4a1b40c','e0fac478939cd69f45ba4e19aef0eae8d5a235d5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.331b9eb9ca800b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
