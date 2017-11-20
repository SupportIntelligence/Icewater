
rule k3f4_169185b392000b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.169185b392000b30"
     cluster="k3f4.169185b392000b30"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor malicious"
     md5_hashes="['05e23093440f74050de935ba22e663f6','230440ab7d9b4693fbdc34c06d239666','fc1dcc0b90729fb4f50ecb7d5ab6992e']"

   strings:
      $hex_string = { d902b60f40019102c50f4706e102e30f40011901f30f97045102fc0f4d06510224105706a900d700650631023f10e205a9003c097203a9004c101300c901570b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
