
rule m3e9_12b1ad1edee31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.12b1ad1edee31932"
     cluster="m3e9.12b1ad1edee31932"
     cluster_size="24"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys zbot trojandropper"
     md5_hashes="['0f90735f95486737b6967b1a127927db','30e3e9908582bc229e5349b21f37cefb','c40c0889e8a2a3cfbf11e44f4fd60de5']"

   strings:
      $hex_string = { 45eb9840d4c141d44046c14242464643d442054153dd43d8434944ab4ca797f04a3f4d474ad62a084bc74b634a4e4d4dd5ec47fbd64c8d483d2e4bceb54ba14e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
