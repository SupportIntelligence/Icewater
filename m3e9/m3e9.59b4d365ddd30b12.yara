
rule m3e9_59b4d365ddd30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.59b4d365ddd30b12"
     cluster="m3e9.59b4d365ddd30b12"
     cluster_size="89"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys malicious"
     md5_hashes="['0710ce40114627548535cff62439f7ea','076570cd64344492b2417e9ad36372e5','81a559641ada68c486893209e13816b6']"

   strings:
      $hex_string = { 9a7f80c1a1a4dcbebcdcbebcccb2b1ab96958b7374694e5162484b9f8384e4c8c86b585aced0d1929596ffffff0f1212f5ebdef9efe1f5e9daf4e8d8f6ebd9f2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
