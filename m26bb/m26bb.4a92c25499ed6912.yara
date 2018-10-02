
rule m26bb_4a92c25499ed6912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.4a92c25499ed6912"
     cluster="m26bb.4a92c25499ed6912"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious attribute engine"
     md5_hashes="['396b174921e940f8f2be29e8cd080df3cc25090c','7576b21526156872138ad101321020972d8cac0e','6ec8aac6a1314a421f2a28cf9c66efd0ad15b925']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.4a92c25499ed6912"

   strings:
      $hex_string = { f2abd9831f81f17f520e5181f68c68059b8945fcc745e067e6096ac745e485ae67bbc745e872f36e3cc745ec3af54fa58955f833c0eb038b4df00fb690b8a442 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
