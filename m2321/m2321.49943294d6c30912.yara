
rule m2321_49943294d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.49943294d6c30912"
     cluster="m2321.49943294d6c30912"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['05a6ed66f48a1311b8e4fd84d7ce3aca','07c2166393ad3f242d893822b43b887e','e1c769e524071f42ab550b514fa55bd9']"

   strings:
      $hex_string = { b6a73d257c92734e6a995647ffc21edc55e59a405483105c7e6fe90896904fc11593e3da8950cc028cec510da129215bd8bbc3879e236404f35a306d2b5dea82 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
