
rule m26bb_19f0c4bac9800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.19f0c4bac9800b32"
     cluster="m26bb.19f0c4bac9800b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="risktool systemtweaker riskware"
     md5_hashes="['c5e2ca516b1fc70525a124518fbc18259eaec5c7','1664b09ba6dd6b4811327fb50e4d3d24afb0ba30','7fc9c9a81dd856973741294ab43b17fa7f9d91eb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.19f0c4bac9800b32"

   strings:
      $hex_string = { 39058ce54000750768d0d94000eb0150e8abfdffff83c4145dc3cccc558bec5756538b4d100bc9744d8b75088b7d0cb741b35ab6208d49008a260ae48a077427 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
