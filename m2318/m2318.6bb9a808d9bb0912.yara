
rule m2318_6bb9a808d9bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.6bb9a808d9bb0912"
     cluster="m2318.6bb9a808d9bb0912"
     cluster_size="16"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['11191c6c9afa6862c8b147e5fdda30a5','245093f0b46c970fcab93eaf783f1867','f221d91e7d34e9a26d2572f27cb481e0']"

   strings:
      $hex_string = { 42364337453939353641333746414530344344303941453232384437443436314237314235423246383238393833364438354543344441354638334632333031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
