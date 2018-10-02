
rule m26bf_261496b9ca800b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bf.261496b9ca800b14"
     cluster="m26bf.261496b9ca800b14"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="msilperseus malicious backdoor"
     md5_hashes="['fe473a0a9d3e8ad9e7dbd04bcb63b20205fdc8bc','0e85bbf2280ac989980b27d004f14d12718fdbcd','88d5302fe8b29feadfd72dbc9586b0b32198cd8b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bf.261496b9ca800b14"

   strings:
      $hex_string = { 6179436c61737334335f35003c47657457696e646f773e625f5f35003c4d6f64756c653e0053697a65460057485f4b4559424f4152445f4c4c0057485f4d4f55 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
