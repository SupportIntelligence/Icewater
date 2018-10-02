
rule k2318_27543299c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27543299c2200b32"
     cluster="k2318.27543299c2200b32"
     cluster_size="1887"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['fc7cff39e33db1f7d8e8bf90c410347976fb0242','806806669a7e5de100da3e52637baaa0107d2f56','cb95c6860bcb96a0170e8eaf00ac0e93c526b10b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27543299c2200b32"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
