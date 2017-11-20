
rule m2321_0b94d449044d4a6e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b94d449044d4a6e"
     cluster="m2321.0b94d449044d4a6e"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis hafen mikey"
     md5_hashes="['0666eca51280f018a8af45011cdc28ef','268cd25a6296a58149b737d37a177ef2','e0a879f252ec1d736455e66445fae10a']"

   strings:
      $hex_string = { d8cc566b22acf6a299879fe75e01ae4b162148e9451803bf85442915e46cd19cfcf9725b7428f1fd70b5619d96c38f6937b63ee51ea353306f11ff89b38ca4ab }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
