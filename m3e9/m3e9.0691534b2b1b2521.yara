
rule m3e9_0691534b2b1b2521
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0691534b2b1b2521"
     cluster="m3e9.0691534b2b1b2521"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar midie scudy"
     md5_hashes="['04e68a95350eacd60a764deeff0919bc','0d7a6a26b0864d3fa05a7160630b5787','a57ebc2dad08df369ca062ca63956f86']"

   strings:
      $hex_string = { 3785aa904d662e0af1dd9b5805d4adac99316b8e5c9e0f23ab873ca53e427b8da6b4be16f603f971fd8c6080020e38119491e53db7d0d9a1bc6a786cc9a8349a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
