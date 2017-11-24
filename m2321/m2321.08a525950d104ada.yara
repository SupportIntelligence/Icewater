
rule m2321_08a525950d104ada
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.08a525950d104ada"
     cluster="m2321.08a525950d104ada"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['1da0e11030652f3ff3bef7741608cdb3','298cf2d7a43a4cc67cfae96f7b7fc58a','f6c7f401ed133a861b66638ef3d1ced6']"

   strings:
      $hex_string = { 4d65c24234bf3390a5e33b2c85df61e268abc3ddbcb05bec09ea5f82d9e127eb4035c88341635a3ad0aa2d2f91607280f464b4af00778c92e6ce662316564905 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
