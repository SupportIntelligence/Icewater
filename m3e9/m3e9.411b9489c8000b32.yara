
rule m3e9_411b9489c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411b9489c8000b32"
     cluster="m3e9.411b9489c8000b32"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys jorik"
     md5_hashes="['2c59f0b8b4185b7d569c6620d1ba8988','3108662d9461276d395015ff4183e047','e327eaf2b88304ba7dc0d475d41fffa2']"

   strings:
      $hex_string = { 938f96a6a5bdc0c1c2c2c5cfdbdedee5def7f7b7000000eefdfd33353c3c3f3f3c4648494f527d7e7d7e838e7c8484919191a3a5a4a8babdc6c5c8d3dddee5ef }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
