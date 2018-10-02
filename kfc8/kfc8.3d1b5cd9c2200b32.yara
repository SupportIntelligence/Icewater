
rule kfc8_3d1b5cd9c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=kfc8.3d1b5cd9c2200b32"
     cluster="kfc8.3d1b5cd9c2200b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="riskware andr apbl"
     md5_hashes="['2ab7456e2cf4524948cd00a3ff4f620622f89466','d37c1b88c2d8eba4c2c35934859f9048c44de343','970832fe1c44d34fd23712ec01337a7c6bc8de5b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=kfc8.3d1b5cd9c2200b32"

   strings:
      $hex_string = { 530009364e3107147abec8ba710e19acdbd0cfd1a41290dacc830c2bce4a58d7cdd27860d9d48264d35f8fcbd6aa242281bd3c1873c6c413bfd8430f65bc7f1a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
