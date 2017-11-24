
rule m3e9_299062a0d9bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.299062a0d9bb0b12"
     cluster="m3e9.299062a0d9bb0b12"
     cluster_size="12"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bitcoinminer coinminer bitmin"
     md5_hashes="['0a1d829228d2b78986b9b86697fe5422','324a4fac12bd58014bd84cb8db9f440b','ca0102028ad934688253a2ccf81481af']"

   strings:
      $hex_string = { 5d030ecb50e5cd530dd47ff2839135225f05c627dccabd7c9d7d5763b9c464613bd16a001a55bc474fd63d82218eb71c779980b21d01eb2954ee77d7699b343e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
