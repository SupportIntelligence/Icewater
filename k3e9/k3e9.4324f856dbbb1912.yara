
rule k3e9_4324f856dbbb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f856dbbb1912"
     cluster="k3e9.4324f856dbbb1912"
     cluster_size="128"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['002304a2c5da16ba29951d2d7d51cc25','0bb5ea0b1be9e81e441b3b4516cc167b','66282f85bcefd13d68d22413fca4696f']"

   strings:
      $hex_string = { ac0147657453746172747570496e666f41004b45524e454c33322e646c6c00007d0044656c61794c6f61644661696c757265486f6f6b0000ed01526567517565 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
