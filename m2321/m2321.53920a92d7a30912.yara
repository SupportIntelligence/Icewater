
rule m2321_53920a92d7a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.53920a92d7a30912"
     cluster="m2321.53920a92d7a30912"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="midie mewsspy qakbot"
     md5_hashes="['0de91ee6b73b97f98631d51d48a07843','182b44172413c5a3fe9985854f950700','f44059bb8e6f7ed555fb3ef040acd5cc']"

   strings:
      $hex_string = { d4859b052ef1a1e89fe3f9ed0a1545fbf0417b29eacae79e63d33b07bdd21775320be414432d6750a764b3863d8e8a36d6f80ccbbcc81a0fb0c6fdac711f6b7c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
