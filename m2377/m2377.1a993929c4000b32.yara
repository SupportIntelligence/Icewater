
rule m2377_1a993929c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.1a993929c4000b32"
     cluster="m2377.1a993929c4000b32"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['33b0ad0b7a5105a32fcc883d828edea8','4cfc7958f6f3529ed52e3c7abcd45089','fa4dbc1befb26f6515bb94f24decfa23']"

   strings:
      $hex_string = { 5bd868d1d4d250a744dae9d72e54076293fae7c7048dbdb5d906378085f41a8320dd612a9cac9d118e36c66a67d69069a74a7df1f01cdcb0aad0a964032d3a0f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
