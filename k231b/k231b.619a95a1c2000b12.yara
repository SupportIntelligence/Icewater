
rule k231b_619a95a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k231b.619a95a1c2000b12"
     cluster="k231b.619a95a1c2000b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery script"
     md5_hashes="['3222ac5daabcc33c7a4933250590a962','4b77602c22c62b48630db0ca373c294f','6bb5ecfa55d56a190bdb0bb84d2ae74e']"

   strings:
      $hex_string = { 3c64697620636c6173733d227769646765742d746f70223e3c68343e5a47c5814fc59a205a574945525ac498205720504f54525a454249452036303420353132 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
