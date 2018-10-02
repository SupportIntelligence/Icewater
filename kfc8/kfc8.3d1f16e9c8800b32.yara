
rule kfc8_3d1f16e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=kfc8.3d1f16e9c8800b32"
     cluster="kfc8.3d1f16e9c8800b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="riskware banker androidos"
     md5_hashes="['82e2d5bec999e874dbd057478155367c151f6da6','df5466a9dc54951953f95dddce4bfbf80f2f96a9','8fa12236279873db50458f547043e431948bb4b3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=kfc8.3d1f16e9c8800b32"

   strings:
      $hex_string = { 530009364e3107147abec8ba710e19acdbd0cfd1a41290dacc830c2bce4a58d7cdd27860d9d48264d35f8fcbd6aa242281bd3c1873c6c413bfd8430f65bc7f1a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
