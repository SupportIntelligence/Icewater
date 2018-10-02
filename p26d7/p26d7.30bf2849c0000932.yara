
rule p26d7_30bf2849c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26d7.30bf2849c0000932"
     cluster="p26d7.30bf2849c0000932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious heuristic"
     md5_hashes="['ed16db585b91630fd284053ec20cee63bf36f53d','ac2028f09eb9139475a5ca501d52ab0aa005a27d','2880d47f2dc9ab962e7771421f89298a1b96d198']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26d7.30bf2849c0000932"

   strings:
      $hex_string = { c0f2aef7d14983cdff8bf933d285ff7e278a4424188a1c328acb80e18080f980750b8a4c32014284c9740deb063ad875028bea423bd77cdd5f8bc55e5d5bc390 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
