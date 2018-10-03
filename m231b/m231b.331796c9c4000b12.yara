
rule m231b_331796c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.331796c9c4000b12"
     cluster="m231b.331796c9c4000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script autolike"
     md5_hashes="['43e5c0284a0b01252e8b1e8a01955e8aff3d0c18','2ff933f55fd5db1728e0a0cdacedb9be790423f1','4898a1a7b11d2e458f7fa2e45af809a664c1c2b0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.331796c9c4000b12"

   strings:
      $hex_string = { 28293b0a696d67725b305d203d2022687474703a2f2f342e62702e626c6f6773706f742e636f6d2f2d7a617a717a4f71796163672f556253504e386378654e49 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
