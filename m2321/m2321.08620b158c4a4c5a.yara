
rule m2321_08620b158c4a4c5a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.08620b158c4a4c5a"
     cluster="m2321.08620b158c4a4c5a"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['179ce20c618bba9bf7f7c59105b30355','5c73b6986f7aa1fc897f2d0033a94465','cc148ca5603e82612088b280627f47e6']"

   strings:
      $hex_string = { 4d65c24234bf3390a5e33b2c85df61e268abc3ddbcb05bec09ea5f82d9e127eb4035c88341635a3ad0aa2d2f91607280f464b4af00778c92e6ce662316564905 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
