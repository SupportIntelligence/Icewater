
rule m923_2b1d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m923.2b1d6a48c0000b12"
     cluster="m923.2b1d6a48c0000b12"
     cluster_size="20"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html classic"
     md5_hashes="['0578e19800814709dff87a91e8501c57','093ce0e2e964099ecd43aa082abb278e','b403af83be533ac8042b82a370f61908']"

   strings:
      $hex_string = { 3799c44d61abb44b57dbddf6d5728d7386f51d416df177a9a140c804f0ced3d20851433a707f16b3c924dc6fe80f2bf39054b0e4bb53da5629c72479eadea42a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
