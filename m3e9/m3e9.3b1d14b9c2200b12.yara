
rule m3e9_3b1d14b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3b1d14b9c2200b12"
     cluster="m3e9.3b1d14b9c2200b12"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['20c7bca3f6615c731da82d300d8a052b','5b1f345ed2dbbc079504c9a6e8da13c5','cb735ea74c001b11d74ee840f4d85a57']"

   strings:
      $hex_string = { 4ef85339976228ad3b55fb8ae845bff7f456ff06927949dfa2093a5ad06bc6cd8b5f9b9c5c70ba035d99b7b626b2251e0411a9b38552daea60fa860bc52e0df1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
