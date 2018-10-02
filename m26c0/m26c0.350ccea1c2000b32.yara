
rule m26c0_350ccea1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26c0.350ccea1c2000b32"
     cluster="m26c0.350ccea1c2000b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu malicious qwheyq"
     md5_hashes="['cc21cfd7dcf6201dae044dedc8635dd07bce28eb','c357c11a6043de0d33c29237e3c33de16411f753','b77e6d32224680202ca88cc2009d882bb8fcaad0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26c0.350ccea1c2000b32"

   strings:
      $hex_string = { be443c0c4f66890683c60285ff7fef5f8bceb8200000002bcdd1f92bc150e89b87000033c06689065e5d83c410c38b44240453ff74240c33db85c00f98c34b23 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
