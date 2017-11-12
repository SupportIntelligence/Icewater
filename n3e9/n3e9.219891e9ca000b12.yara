
rule n3e9_219891e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.219891e9ca000b12"
     cluster="n3e9.219891e9ca000b12"
     cluster_size="3083"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadadmin bundler downloadmin"
     md5_hashes="['00162b5a1281efc61c2405ec87040ab2','001dc50314ffb7c727a5117b96dbb58a','00de4b4c9cb5474e2b514d967cf8b5fd']"

   strings:
      $hex_string = { f4c39548a5171de3592ff9fa1455064482b4de940183093ab9c1cdb0e08c5099f54e9f9289e6fdac2097bae97d630daec2414c969ab4dbbba8b354d837f2cf3c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
