
rule m26bb_136a660f019ff111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.136a660f019ff111"
     cluster="m26bb.136a660f019ff111"
     cluster_size="589"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious attribute"
     md5_hashes="['15652f8eaef518ee93865351b2c7a39b632d33c8','9b77d05a7c058e9e090db961b59a58f975c00956','e3746ce99c6c1e9eb0fc4aaee90713a6d178b23f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.136a660f019ff111"

   strings:
      $hex_string = { 79dc72fb36cca732088a4a7e926306ec96155a7621c2e6f191dfe2be1dde0cf7ea73b826d7a4d9db99141ba6bf2d6e3cb51e9ee4feced666123b200fa9ed4c97 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
