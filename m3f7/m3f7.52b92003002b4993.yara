
rule m3f7_52b92003002b4993
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.52b92003002b4993"
     cluster="m3f7.52b92003002b4993"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['3c84c99237b7c7d9a1b79ecee7ba3c90','50b4e0dec5d08aef25e4cfccc8af9cb0','f5e33c96fab0f410c5b86ee17d900bf5']"

   strings:
      $hex_string = { 44726f70506174682c20300d0a2f2f2d2d3e3c2f5343524950543e3c212d2d2e64258f75cffa41103f3fbc466347ba5e18804ea05d6df1e750b062dbe44d0204 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
