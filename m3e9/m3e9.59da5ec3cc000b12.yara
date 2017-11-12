
rule m3e9_59da5ec3cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.59da5ec3cc000b12"
     cluster="m3e9.59da5ec3cc000b12"
     cluster_size="127"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['01368f8efef9e9afc94f095b53675326','02b2b2be13236620aaa962d2f6430793','2b4009692d4849e336f7187f2d03584c']"

   strings:
      $hex_string = { 68656d61732d6d6963726f736f66742d636f6d3a61736d2e7633223e0d0a202020203c73656375726974793e0d0a20202020202020203c726571756573746564 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
