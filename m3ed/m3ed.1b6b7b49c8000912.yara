
rule m3ed_1b6b7b49c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.1b6b7b49c8000912"
     cluster="m3ed.1b6b7b49c8000912"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['0f96c0c2cc954542ed9053e249f1902d','15dbd00fa4b01eb86574800f75d56c21','c188ee6977fb54d6ba70ccdef67750c9']"

   strings:
      $hex_string = { c20c00558bec51515356578b7d088d470433db8d4df88945f8885dfce875e4ffff8b771c3bf37429ff156cb0125d33c9394604740b8bce8b760885f675f2eb11 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
