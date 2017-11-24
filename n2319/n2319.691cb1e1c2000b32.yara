
rule n2319_691cb1e1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.691cb1e1c2000b32"
     cluster="n2319.691cb1e1c2000b32"
     cluster_size="48"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['01eabd6fe095806a2e2c7bbb5ec0c489','0a4e7898a9af46073f3dd8cb8b89af7d','77957469e4bb4f21336431454c800824']"

   strings:
      $hex_string = { a4d180d0b826233736393bd181d0bad0b53c2f613e0a3c2f6c693e0a3c6c693e0a3c61206469723d276c74722720687265663d27687474703a2f2f6b61747776 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
