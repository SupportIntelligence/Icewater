
rule m3e9_211db48fc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.211db48fc6220b32"
     cluster="m3e9.211db48fc6220b32"
     cluster_size="438"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbran autorun"
     md5_hashes="['007d745540f8963ad7fd374ec23f3673','00a4d78cd472d994da43cb9feb43071e','1eb1bc900a8d08029c7d4302071bed50']"

   strings:
      $hex_string = { 42364051a9cdd3d1b5b4b4a9aa785653521016b1f3f4f4f4fcf0bc45260000002180848483bbd1ead0eceeecb17c7c717070b7ecf0eccfcdb7b7a9a9a7665b59 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
