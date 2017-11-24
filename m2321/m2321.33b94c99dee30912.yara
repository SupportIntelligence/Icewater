
rule m2321_33b94c99dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.33b94c99dee30912"
     cluster="m2321.33b94c99dee30912"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['116311298872347699164815ed004622','528884a74e0484ad3e0ed443d1b5b665','d8a6683944ac9227b7cca9f2caefbdfd']"

   strings:
      $hex_string = { 33af8d4ae68cbc5e046ced6d533ca1e0dabae891a541782d4d604bd136a62b862fd42c9ea3ebe9d330bbaaae3b74cfdefac6c46f395fac0513f349a489280637 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
