
rule o3e9_72ddbec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.72ddbec9c4000b12"
     cluster="o3e9.72ddbec9c4000b12"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock tdss nabucur"
     md5_hashes="['0a9f6bf789e752259f3660b4a902f27c','235b5494f1362d26a62df7bd4c24cfac','d8bc7bf6b628eb9e6886a3d124f504bf']"

   strings:
      $hex_string = { e6e400e3e6e400e2e5e300e2e5e400e8ebe900aeb0b1006a574a0060341c00442821001511140011141c0047494d00e7e9e700edf4ee00eef4ee00eef2ee00e1 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
