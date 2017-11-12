
rule m3e9_33349619c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33349619c2200b32"
     cluster="m3e9.33349619c2200b32"
     cluster_size="116"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbran autorun"
     md5_hashes="['0c1cc3f0e2844cd923ab59a98633585b','0c50d9b5c500dcbcae418e8315b740ed','84f62a1ca7761695add0e186566afdad']"

   strings:
      $hex_string = { 42364051a9cdd3d1b5b4b4a9aa785653521016b1f3f4f4f4fcf0bc45260000002180848483bbd1ead0eceeecb17c7c717070b7ecf0eccfcdb7b7a9a9a7665b59 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
