
rule k3e9_13959250dc827916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13959250dc827916"
     cluster="k3e9.13959250dc827916"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['1337013595cbe881275545d141c3f957','486f3c801bb200d1908eee8e0c27f08a','f030d979d2b60a6c8a00b069c41c2a86']"

   strings:
      $hex_string = { 8dee51a33bf42d11353ad5ed15da7a78a6f9f80e6d69cf328ceaa75767131be0c599250412d0866563565ea8b02a3d292b7be1bd99f594f6ce6c620dbc31b344 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
