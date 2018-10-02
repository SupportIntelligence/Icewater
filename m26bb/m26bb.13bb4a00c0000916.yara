
rule m26bb_13bb4a00c0000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.13bb4a00c0000916"
     cluster="m26bb.13bb4a00c0000916"
     cluster_size="82"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mywebsearch toolbar mindspark"
     md5_hashes="['e3a2a617993764dad8838349a98a6054aa6609fd','83801a645377f2c94f346fc0d1844086e9fdb0dd','dbb5bcc6ab852d6584dcc9148a64caf18c86be81']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.13bb4a00c0000916"

   strings:
      $hex_string = { 45fc3bfb7c8e33db8bf3c1e6060335e02541008b0683f8ff740b83f8fe7406804e0480eb71c646048185db75056af658eb0a8d43fff7d81bc083c0f550ff15ec }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
