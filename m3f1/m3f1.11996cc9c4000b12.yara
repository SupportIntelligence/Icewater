
rule m3f1_11996cc9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f1.11996cc9c4000b12"
     cluster="m3f1.11996cc9c4000b12"
     cluster_size="11"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos appad triada"
     md5_hashes="['203b74a2df3ccc1593fc83f1a6cdfdb7','25573a5e3ed91c8e37789bd60af2b004','f797a3c5789179d5266c3c8c4a688f6f']"

   strings:
      $hex_string = { cb23cf37440e093e82d01a21240d6ed9f31dfb267b4a74b14ec040f06225e6ee39966c2933a6930ca37a5ab0d195b66fb39328b5be4904cc5835839d5379eab4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
