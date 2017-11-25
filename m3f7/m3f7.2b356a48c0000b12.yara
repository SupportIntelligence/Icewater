
rule m3f7_2b356a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b356a48c0000b12"
     cluster="m3f7.2b356a48c0000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker cryxos html"
     md5_hashes="['3f9aa0a154cd2668b7766b02cb8ba626','4eeed9012d78eeb0cc796abb7e4cf7e5','b4041266a5114a9f50ede6da0cf3d45a']"

   strings:
      $hex_string = { 726f756e643a2075726c2827687474703a2f2f332e62702e626c6f6773706f742e636f6d2f2d4657654a4d6b44483150672f55634754344e68336a53492f4141 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
