
rule i3e9_27937689cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.27937689cc000932"
     cluster="i3e9.27937689cc000932"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['60f6d0f46c39930ce63cf89c9d33b390','8a6b351cd43b79120352cb2a367a1c6d','c12b9b0ca478d613ecf2ae9ed9634495']"

   strings:
      $hex_string = { 2f6f8b0dc63577c7d86bdb628763ec508c5dda16ab0c36dfa3af6c8b7d3bc672fd1ffefe1f0af962bd7c7471b1549d2b84c9d1b1c2d1fc1787e62a95f8963e56 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
