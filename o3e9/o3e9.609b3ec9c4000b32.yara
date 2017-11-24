
rule o3e9_609b3ec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.609b3ec9c4000b32"
     cluster="o3e9.609b3ec9c4000b32"
     cluster_size="35"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock symmi nabucur"
     md5_hashes="['0418dd179e1e7c08d96934dd4961170f','3587d6ec5bd0856fdb0ecdc0d7b2f331','b6b6f3001ba96162ea994dce8a9236e5']"

   strings:
      $hex_string = { e6e400e2e5e300e2e5e400e8ebe900aeb0b1006a574a0060341c00442821001511140011141c0047494d00e7e9e700edf4ee00eef4ee00eef2ee00e1e7e300e1 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
