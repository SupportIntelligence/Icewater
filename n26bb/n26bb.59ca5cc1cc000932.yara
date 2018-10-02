
rule n26bb_59ca5cc1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.59ca5cc1cc000932"
     cluster="n26bb.59ca5cc1cc000932"
     cluster_size="161"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom filerepmalware"
     md5_hashes="['04231d471513c7404fc8bbc1de4961a34e752527','16258412d3d4330b3af4253f0b24e2174f764dd1','0d1342d7165331a4d08b0538523e881b063c3bf7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.59ca5cc1cc000932"

   strings:
      $hex_string = { 8d46185750e8ceccfeff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
