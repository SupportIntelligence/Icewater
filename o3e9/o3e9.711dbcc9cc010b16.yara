
rule o3e9_711dbcc9cc010b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.711dbcc9cc010b16"
     cluster="o3e9.711dbcc9cc010b16"
     cluster_size="367"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lethic malicious ayzg"
     md5_hashes="['009b550c27444337e0842abd5600f82f','012f194b6a390ae40b54e427a1d6ac9e','123a6e53186fe76be6999ceeae574b93']"

   strings:
      $hex_string = { 1a3d250c090034d27f5f3158099cf3ebc9650bc03cf826925af1fe9e2397845dab0f22e0f988a002b519b8f766d85e133dc47dc3d8bad173b4736e31d49c317c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
