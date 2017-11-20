
rule m3e9_0b11a989c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b11a989c6220b12"
     cluster="m3e9.0b11a989c6220b12"
     cluster_size="87"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="byfh memscan ageneric"
     md5_hashes="['076071150dff4b88adaef79e9c2cf2b6','07949b9e68d14fbca1f925c1b1197000','47c22fba9248606493d14758b2297f4d']"

   strings:
      $hex_string = { e29b310a3f816dca0c58304df3e0dcc02d438284a693b9bbd5415eb094aae50768385d90edeb0824652843a1830f6ad297b6a84b7210455535afd1cfcb2e1a91 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
