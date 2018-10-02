
rule k2319_105b0699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.105b0699c2200b12"
     cluster="k2319.105b0699c2200b12"
     cluster_size="49"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['09290d00cc77861ce2c6c8cd9bd4e43dc62b5c25','189b3656a98e68ac1fed3ca50ed1c57354a64751','ac1245625a6e963d1048cfd2c2b0ef628342207e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.105b0699c2200b12"

   strings:
      $hex_string = { 495b585d213d3d756e646566696e6564297b72657475726e20495b585d3b7d76617220453d282831302e343745322c3078313541293e3d35362e3f2837392e33 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
