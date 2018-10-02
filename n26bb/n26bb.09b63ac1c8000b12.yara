
rule n26bb_09b63ac1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.09b63ac1c8000b12"
     cluster="n26bb.09b63ac1c8000b12"
     cluster_size="344"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom malicious"
     md5_hashes="['e0ff87505a1ac554efcd59d894ac53252644f505','3dfbcf62b67d6a6742f2182e95b94b4b2e7f1c50','4654105093935bf70aeef282a2b1a4b188aa8689']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.09b63ac1c8000b12"

   strings:
      $hex_string = { 4129211c19171615141312121111111010100f0f0f0f0e0e0e0e0e0e0e0d0d0d0d0d0d0000000100000070304200020000007830420003000000803042000400 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
