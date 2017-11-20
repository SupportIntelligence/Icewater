
rule m3e9_01915b6ac91ad135
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.01915b6ac91ad135"
     cluster="m3e9.01915b6ac91ad135"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar zusy scudy"
     md5_hashes="['2f040b6177b6cceca497804830725c0b','7b3e9d3cf83ea47d81861a7e438738ae','f84af9cdd49b89c4da8f749c1f72b602']"

   strings:
      $hex_string = { c751fc633cd02b5c2f809c1000afad760136a749c618e065bb8cc01e42f52e2092cff3db5ff9f2d53f503e0afd892224403964f7910713b47f1922795ba37260 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
