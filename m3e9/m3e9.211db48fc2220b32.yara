
rule m3e9_211db48fc2220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.211db48fc2220b32"
     cluster="m3e9.211db48fc2220b32"
     cluster_size="55"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbran malicious"
     md5_hashes="['02cf92e9cf85155454ead90d94eeb04d','04cc7f4b529a4f9a99a2ddb3c91be8eb','8ae5febbcd5b86f4a214fc109df7f018']"

   strings:
      $hex_string = { 42364051a9cdd3d1b5b4b4a9aa785653521016b1f3f4f4f4fcf0bc45260000002180848483bbd1ead0eceeecb17c7c717070b7ecf0eccfcdb7b7a9a9a7665b59 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
