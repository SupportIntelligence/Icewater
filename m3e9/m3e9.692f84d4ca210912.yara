
rule m3e9_692f84d4ca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.692f84d4ca210912"
     cluster="m3e9.692f84d4ca210912"
     cluster_size="113"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['02a28c7b900f688d4aa29f565c98c20a','095f6f482231694b4694cac15740b004','6dfff8a63d3d751a04e3704cb80b6018']"

   strings:
      $hex_string = { c1ad5ed58f6d260c1f0d6fc4be8e0096b4998b7a6934ebae574635d00bc9401472a7b0e4eae79eb84536c6dff44c5955e9f95d900a60e5771788815606e0647f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
