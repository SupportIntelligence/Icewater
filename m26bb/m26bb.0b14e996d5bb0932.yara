
rule m26bb_0b14e996d5bb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.0b14e996d5bb0932"
     cluster="m26bb.0b14e996d5bb0932"
     cluster_size="272"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundlore bundleinstaller downware"
     md5_hashes="['c66fe57c07a08eafa38030eed3d5e7635364523d','6baf370db2a88e63ba47a7a396678be0274014f9','38b85ad30235d94230dbd179c51d704f0b3d994d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.0b14e996d5bb0932"

   strings:
      $hex_string = { 3bd37c088bc299f7fb004603005604f6056cc64100015e7414803930750f6a038d41015051e8313affff83c40c807dfc0074078b4df8836170fd8bc75f5bc9c3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
