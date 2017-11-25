
rule i2321_27937689cc018932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.27937689cc018932"
     cluster="i2321.27937689cc018932"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['1a2785bf721a0057da030313713aaaa1','1e0efffc785e7637aa3c412568ac16a5','cdb00b8e4ac18737030aa7161adb7509']"

   strings:
      $hex_string = { 2f6f8b0dc63577c7d86bdb628763ec508c5dda16ab0c36dfa3af6c8b7d3bc672fd1ffefe1f0af962bd7c7471b1549d2b84c9d1b1c2d1fc1787e62a95f8963e56 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
