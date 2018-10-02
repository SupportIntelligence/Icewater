
rule k2319_101a9299c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.101a9299c2200912"
     cluster="k2319.101a9299c2200912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['262c65f3cffa36415f651f5c7546a2f19a14c1ad','84935c575484f375fc47d5f57667afec02140fa9','3b09afdf6bba6ccd3f848645fca89d5f3c4a4a92']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.101a9299c2200912"

   strings:
      $hex_string = { 646f773b666f72287661722044345420696e2055336a3454297b6966284434542e6c656e6774683d3d3d282830783146372c312e3136354533293e307839423f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
