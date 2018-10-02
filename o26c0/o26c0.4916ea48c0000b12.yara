
rule o26c0_4916ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.4916ea48c0000b12"
     cluster="o26c0.4916ea48c0000b12"
     cluster_size="215"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious genericrxer kryptik"
     md5_hashes="['6533196011104542b566e2e64517b368be302c22','3b53c18879db0bcbb622f4eb2ec005468e6905d1','8f9bf2779ca57dee15a194bfac7a8f12c43f3baa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.4916ea48c0000b12"

   strings:
      $hex_string = { 3145ed6fe119da63b7c7a57e384fa11112d8fa8d54b57b8151d77cd2c5c19b36ae676e3ade68d66ddbc9e5e1fd7fc0bc768b2c3e86fce02a73b6dd161a902193 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
