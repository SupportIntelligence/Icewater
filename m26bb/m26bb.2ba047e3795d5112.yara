
rule m26bb_2ba047e3795d5112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.2ba047e3795d5112"
     cluster="m26bb.2ba047e3795d5112"
     cluster_size="113"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="techsnab malicious unwanted"
     md5_hashes="['0bcc5d2298bcccacf557bf450aad99e0b6ca52b8','79c6aaed03fcfeb2aa541a9eeda8542cd4bcb7e8','1cab09be7f4e922e0978f4bb2d4a6d36b8a43934']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.2ba047e3795d5112"

   strings:
      $hex_string = { 18eeba071bd845a5f8f9efe855a0bf5aaf49218dfeb16b6f4b60ecdadbf235d7dec570ed1da2a4772e925015cef5267232961e781f0cc3ff2989a1f47ef63a69 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
