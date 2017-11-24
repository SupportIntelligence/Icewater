
rule m3e9_316339678dbb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316339678dbb1112"
     cluster="m3e9.316339678dbb1112"
     cluster_size="78"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['01f32f295cfd6eee9fdbf26721902721','02d638c673f262ad2b4188cb73bd2a7b','a264207e2a7b6118eec8b3641c680965']"

   strings:
      $hex_string = { 1bc806c0fdcf5fe54c5ac7996baa2996a84939f7a3178340d9570450c99822ae13192d07addcb53ed8f1f5b18a78739cadde15e490862c4f94e079a78926afe1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
