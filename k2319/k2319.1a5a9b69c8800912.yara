
rule k2319_1a5a9b69c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a5a9b69c8800912"
     cluster="k2319.1a5a9b69c8800912"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['661f6e6a487cd52ea720e2c0796632dfbb1e29ee','5375fad3714fa8ada71b6326c0a037ccde371c14','196704d6edb4fe787c075f5018165f152d1d7b88']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a5a9b69c8800912"

   strings:
      $hex_string = { 28322e343045312c3078323332292929627265616b7d3b7661722053394139693d7b27753952273a224a222c274f3869273a66756e6374696f6e28712c43297b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
