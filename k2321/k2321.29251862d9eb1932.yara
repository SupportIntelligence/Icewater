
rule k2321_29251862d9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29251862d9eb1932"
     cluster="k2321.29251862d9eb1932"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['0fcdfab48b6e1fca6561b78344c69769','165d185e960e057056da1be77c00eff6','f12151ba8eb763a7fe5ff23e14a860e6']"

   strings:
      $hex_string = { 9bd6dc1e71ce629e39e028bdd7445b2d0d5672af89b23a1aac74735b1f75b31af36435aa2257e8c8c968df6cb447f66ebc1d8e5dfb43ba4b8a0bf57a54809169 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
