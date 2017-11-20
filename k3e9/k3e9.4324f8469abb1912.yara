
rule k3e9_4324f8469abb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f8469abb1912"
     cluster="k3e9.4324f8469abb1912"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['5f88f647259fa0c3efdb3372b41cf1ab','b08e7ce4dc6026ad4d64c16c1e6fcad0','ec0034ad79ffd38ee80c648bbe5047a3']"

   strings:
      $hex_string = { ac0147657453746172747570496e666f41004b45524e454c33322e646c6c00007d0044656c61794c6f61644661696c757265486f6f6b0000ed01526567517565 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
