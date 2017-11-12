
rule n3e9_12d932e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.12d932e9ca000b12"
     cluster="n3e9.12d932e9ca000b12"
     cluster_size="535"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['032c87bcbd631db508c642d59a8a16e8','03a62dd744d574b3500f08c8370c98bd','1af008f23c88b022f32caf7950fdf67e']"

   strings:
      $hex_string = { 5a5ced4eb93ea37fd68165f48bb3ec1fc459c79cf530aa98f66043960c54b77bc8a2641b5d4dee79994ceb5881a467ace7320b61df0390f772ae1d171acad97c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
