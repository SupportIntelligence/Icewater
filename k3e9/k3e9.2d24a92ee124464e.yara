
rule k3e9_2d24a92ee124464e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2d24a92ee124464e"
     cluster="k3e9.2d24a92ee124464e"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['2760b7b9027b66684e9fce4077411fce','3033d579a3a8f86956003ce6b30ddec0','3033d579a3a8f86956003ce6b30ddec0']"

   strings:
      $hex_string = { 56fc8955f88b55f4f6c201895d0c7574c1fa044a83fa3f76036a3f5a8b4b043b4b08754283fa20bb0000008073198bcad3eb8d4c0204f7d3215cb844fe097523 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
