
rule m3e9_13b630acd7a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b630acd7a30912"
     cluster="m3e9.13b630acd7a30912"
     cluster_size="21"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz vrce"
     md5_hashes="['03c8847e14ae70c306a0c248110f1961','07c77d4c76c7eba66eb2ccbf518d54c1','a64e38ca32666a2f729b0ee35f5d0c5f']"

   strings:
      $hex_string = { 7cccf0b5d764236f7636e68aa479b1ed6b1ae24e108b7399ea437fbaaac8f3ecda212c7090f133a0dcad47450386d52b54b8d3ab667a0522b2a568af4b7db996 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
