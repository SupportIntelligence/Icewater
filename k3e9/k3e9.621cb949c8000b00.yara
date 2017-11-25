
rule k3e9_621cb949c8000b00
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.621cb949c8000b00"
     cluster="k3e9.621cb949c8000b00"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob vetor"
     md5_hashes="['0a3591a3ff65543cee56893f672ef5b9','0c7d8ae6cbb3ca10391595b7baf56ef0','abbbfc3d52fb4f8d3d4246dd6e47bf2c']"

   strings:
      $hex_string = { 00740069006f006e00200031003900390036002d003200300030003100000022017d0001004c006500670061006c00540072006100640065006d00610072006b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
