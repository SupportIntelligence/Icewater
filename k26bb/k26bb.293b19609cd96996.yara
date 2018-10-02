
rule k26bb_293b19609cd96996
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.293b19609cd96996"
     cluster="k26bb.293b19609cd96996"
     cluster_size="233"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore dealply malicious"
     md5_hashes="['4170569a6d0390a7cc797629482711be93def991','fc3cb28d6f5ab34581a9e7e10dd526ad95d13365','4ee7206b88a4ff4a1895fd9c42c53424a8f89991']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.293b19609cd96996"

   strings:
      $hex_string = { 15931601f039c851002b8cd3d89f8e678868c4ffcb5ca3593dba4ca688293ee5280420cce452fc7e3b56a766e29a7bf4ddd5c59126469510c98186a972783196 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
