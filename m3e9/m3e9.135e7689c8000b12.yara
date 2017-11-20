
rule m3e9_135e7689c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.135e7689c8000b12"
     cluster="m3e9.135e7689c8000b12"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi aaeh"
     md5_hashes="['49f00918380da7f112913c96b5499c48','a5feeca829e56ad3056c9d3d95a66d51','e9658a5f202d40155f057d0972a3ebab']"

   strings:
      $hex_string = { 77305470afb0b3b1a25f5fa2bbc0d5d5f11180d69726ddd9b9812900000000000000000000000089f2f9f9f1fea2727350516267757476705d5b6c9fb2bcbdd8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
