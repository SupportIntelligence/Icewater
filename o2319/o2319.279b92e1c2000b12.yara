
rule o2319_279b92e1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.279b92e1c2000b12"
     cluster="o2319.279b92e1c2000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos coinminer coinhive"
     md5_hashes="['4f29c860bd89afc328432655828a9d9442780ff1','db5477cc7ae14c01ebfa56f20b74d0f57c7c2ff5','9698c7fe8d22d4979a2defea9f2150e2d9278fb9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.279b92e1c2000b12"

   strings:
      $hex_string = { 746820776f726453706163696e67207a496e64657827293b0a0a456c656d656e742e4353535f4c454e475448203d202f5e28285b5c2b5c2d5d3f5b302d395c2e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
