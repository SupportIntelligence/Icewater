
rule j3e9_41166826ca230b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.41166826ca230b32"
     cluster="j3e9.41166826ca230b32"
     cluster_size="37"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="heuristic corrupt corruptfile"
     md5_hashes="['0aa867c82ca6b07de28337bbe9f1c4f1','0b4628abe57859119504c633d6611470','7d7c29fdc103e1043f0d5635ae54f5aa']"

   strings:
      $hex_string = { c1f9027809f3ab89d183e103f3aa5fc39069152cc04000058408084289152cc04000f7e289d0c38bc053565789c65085c0745131c031dbbfcccccc0c8a1e4680 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
