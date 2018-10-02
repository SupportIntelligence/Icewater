
rule k2319_58120ce9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.58120ce9c8800912"
     cluster="k2319.58120ce9c8800912"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['9e77631ed49450fb07d87ae475f5ed18202d7069','6dcb5202f3e393ffa04fefa2c71efd82d7f10a56','a3ef7909219151fec908f8377bcc4e64e13ae2e8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.58120ce9c8800912"

   strings:
      $hex_string = { 705d213d3d756e646566696e6564297b72657475726e20755b705d3b7d766172204b3d282832362e2c312e333938304533293e283130352e2c3078323246293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
