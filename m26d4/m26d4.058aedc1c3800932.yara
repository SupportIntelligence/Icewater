
rule m26d4_058aedc1c3800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d4.058aedc1c3800932"
     cluster="m26d4.058aedc1c3800932"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ramnit malicious attribute"
     md5_hashes="['aa3ca84107eb8bc80ff8baad1abc86dfeb0560b0','5da67ad2b30ca4888cad4dff81f64baee36580af','6df129982edc65cf3df130ccec6ac3f624b80567']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d4.058aedc1c3800932"

   strings:
      $hex_string = { 0a6685f67405663bf074ca0fb7c80fb7c62bc1807dfc0074078b4df8836170fd5f5e5bc9c3cccccccccc8bff558bec5633f63935a065410057757f33c0397510 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
