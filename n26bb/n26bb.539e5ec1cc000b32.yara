
rule n26bb_539e5ec1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.539e5ec1cc000b32"
     cluster="n26bb.539e5ec1cc000b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack aicop patched"
     md5_hashes="['e0b7879230803e17a322f85a35e626bae4927ace','f04a85eea09b781996b90c98702d10d65f361820','b73f58b9149c59f2f6e1cf9c2423733825259457']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.539e5ec1cc000b32"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
