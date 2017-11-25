
rule m3e7_13565359dee30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.13565359dee30b32"
     cluster="m3e7.13565359dee30b32"
     cluster_size="38"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ludbaruma regrun backdoor"
     md5_hashes="['0935b5d105b6be1c066ad9099b33f286','09a92b62725fec3387a8e88466a54df7','99c8e0eb640d02e975097dc94221c3ab']"

   strings:
      $hex_string = { c0f7d833c983ff030f94c1f7d90bc16685c07415ff75e8ff75e0e8e714feff8bd08d4de8e8e914feff6a015803f0e910ffffff684d0f4200eb30f645fc047408 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
