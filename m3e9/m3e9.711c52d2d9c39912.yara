
rule m3e9_711c52d2d9c39912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.711c52d2d9c39912"
     cluster="m3e9.711c52d2d9c39912"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['2e4977af972358f80f1978e1aa597b01','4a0098a8d406f8c4083f01e557b80814','f75e2604f8a296e2291eab60cf6bb916']"

   strings:
      $hex_string = { c07ed58b6c24243bfd7dcd66f70680ff75178a164788134883c6024385c07fe78bc75f5e5d5bc218008b4c24288b542414512bef6a00555350566a0052e89e0d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
