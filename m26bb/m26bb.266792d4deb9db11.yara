
rule m26bb_266792d4deb9db11
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.266792d4deb9db11"
     cluster="m26bb.266792d4deb9db11"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious ccmw"
     md5_hashes="['38f27081f65dad5d1dff83d5c61cfe0c9a901e00','b7d827cf17a4f3e073925688bb226e51ce438238','0d564e9f38e6216a5c24ea7529d6badac1bd60f5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.266792d4deb9db11"

   strings:
      $hex_string = { 1e24335f3a4ff99d462bad8a914bdbb30222056a8c252c9354723570cee0b053fbeabd0a78e33b0960e1c57a3dc2c8216210d1cfcc0f5c5ebec3b5eb94a1f06c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
