
rule k2319_5b1094e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5b1094e9c8800b12"
     cluster="k2319.5b1094e9c8800b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['36658088d5636dfd6c0f57a152b1c942d4a98d07','5f2cf32af7bd06d7abd99740e4ccc4bf1ffc2459','10665e6d234574cd898d9a725b7c6043358aaaf0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5b1094e9c8800b12"

   strings:
      $hex_string = { 344531293f2271223a28307842382c307839292929627265616b7d3b666f72287661722041376a20696e20473667376a297b69662841376a2e6c656e6774683d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
