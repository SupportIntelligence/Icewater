
rule k24c1_5336a29596fb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k24c1.5336a29596fb0912"
     cluster="k24c1.5336a29596fb0912"
     cluster_size="35"
     filetype = "Dalvik dex file version 035 (Zip archive data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos smssend trojansms"
     md5_hashes="['000ea76dd17d405a9361c549f63a9cd6','0ac505e0b32fb1d9d02178fe408a28c3','98d155e38e28f7e303d30d8d25eee407']"

   strings:
      $hex_string = { 0b70bc3e9c47941eb46f5331ebadc7bf6133e4b8a1ed2664c0dae3738781b1a4dee6300a168f9e6dab3a7f4df70539b9d04a652db1f785ea9af4f3fbd2cae882 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
