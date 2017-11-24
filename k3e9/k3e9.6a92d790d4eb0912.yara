
rule k3e9_6a92d790d4eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a92d790d4eb0912"
     cluster="k3e9.6a92d790d4eb0912"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis malicious"
     md5_hashes="['0d288d1d4bbbf2d66ffb7d60c36523a8','2c71c5e93ead75e66b9f9f925d59e358','dcb0d79cfae2da78a12fef391949ee94']"

   strings:
      $hex_string = { c07c2b568d7041c1e6055703f18d78018b0685c07410837efcff750a50ff150430001083260083ee204f75e45f5ec3518b4424085355568b981408000057895c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
