
rule m231b_29956a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.29956a48c0000b12"
     cluster="m231b.29956a48c0000b12"
     cluster_size="36"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clickjack"
     md5_hashes="['1a617cbc34a3b0ca2c3aa56bc9eae187','1d63e4576ac9773da4516d91410d2e7a','73bdd96240e81848408c67c8ae3316d6']"

   strings:
      $hex_string = { 2e676574456c656d656e74427949642822626c6f672d706167657222293b696628706f73744e756d3c3d32297b68746d6c3d27277d666f722876617220703d30 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
