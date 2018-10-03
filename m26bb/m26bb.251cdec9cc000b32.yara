
rule m26bb_251cdec9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.251cdec9cc000b32"
     cluster="m26bb.251cdec9cc000b32"
     cluster_size="108"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jaiko malicious riskware"
     md5_hashes="['3f04d802d0b4619d8a51f8806200b4bc32a092d4','1ac9265632068e86281cbea77c67283ce15f8153','1efb760bf62db72e41c90c82db24197d6086ce2f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.251cdec9cc000b32"

   strings:
      $hex_string = { be443c0c4f66890683c60285ff7fef5f8bceb8200000002bcdd1f92bc150e8fb80000033c06689065e5d83c410c38b44240453ff74240c33db85c00f98c34b23 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
