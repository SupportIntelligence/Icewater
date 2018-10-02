
rule kfc8_131a9789cd420b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=kfc8.131a9789cd420b12"
     cluster="kfc8.131a9789cd420b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mydoom email emailworm"
     md5_hashes="['17dc2a8cb5044ffc5c52e387abc0a757abcd8696','2d1a6f977e8fbc8d30290b15cb2dbc8a5433c9c0','7293e00e3765a014f183d9d358e737202f47c3a4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=kfc8.131a9789cd420b12"

   strings:
      $hex_string = { 845c30c2a45e9a31af2d87064beab0ac999d37183658842e8d0049543388b97809fb10b2b695586ea352434f24043e2768a5776234077a127b2f92b9da19ef17 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
