
rule k3e9_6a1e3949c8000b00
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a1e3949c8000b00"
     cluster="k3e9.6a1e3949c8000b00"
     cluster_size="31"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob vetor"
     md5_hashes="['5a80f9b61a979821df6e869c3f3d0891','73df60992d4b45aecb50730991dce22e','f71e42a16712be718b01c35be07c9dd1']"

   strings:
      $hex_string = { 00740069006f006e00200031003900390036002d003200300030003100000022017d0001004c006500670061006c00540072006100640065006d00610072006b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
