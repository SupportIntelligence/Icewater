
rule n26bb_031299a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.031299a9c8800b12"
     cluster="n26bb.031299a9c8800b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ddzb bunitu kryptik"
     md5_hashes="['6b3856702b38d1e2ea37252977f85bc265236819','395cf24a5df6e24c986211918f91cdae78aa52f4','c1316568369c9301e053c133112d660a24f3caee']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.031299a9c8800b12"

   strings:
      $hex_string = { da8bd18a06880242463ac374034f75f33bfb75108819e8e7f6ffff6a225989088bf1ebc133c05f5e5b5dc38bff558bec8b4d085633f63bce7c1e83f9027e0c83 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
