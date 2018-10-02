
rule k2319_501994e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.501994e9c8800b12"
     cluster="k2319.501994e9c8800b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['235323a64ea248158a062ce0883f912a7262ba82','a3ccce31d05b246bf541fa1670cc87cf814f0fac','00e9477c962e8395166d63d97fd1ad6f532f2288']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.501994e9c8800b12"

   strings:
      $hex_string = { 7661722049363920696e205734523639297b6966284936392e6c656e6774683d3d3d28307844413c3d2835372c38342e293f28312e31373445332c225522293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
