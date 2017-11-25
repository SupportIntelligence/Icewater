
rule n3e9_393173c395964b26
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.393173c395964b26"
     cluster="n3e9.393173c395964b26"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious riskware dealply"
     md5_hashes="['0e6353ba1dab81e3a54a6bf6da49fe3e','3973f1d8f1821f33eaf681261687d584','d062bf8f3fca660e335a8c04a1eab41c']"

   strings:
      $hex_string = { 6e00670065002f0043007500730074006f006d002000760061007200690061006e00740020007400790070006500200028002500730025002e00340078002900 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
