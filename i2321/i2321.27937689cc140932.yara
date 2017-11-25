
rule i2321_27937689cc140932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.27937689cc140932"
     cluster="i2321.27937689cc140932"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['49f95858e5e2921f287531231ee8d250','7b6f9faa73b9c855f957ec6ad99f05ee','f92552f81b85f0edc61b292fcf4f304a']"

   strings:
      $hex_string = { 2f6f8b0dc63577c7d86bdb628763ec508c5dda16ab0c36dfa3af6c8b7d3bc672fd1ffefe1f0af962bd7c7471b1549d2b84c9d1b1c2d1fc1787e62a95f8963e56 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
