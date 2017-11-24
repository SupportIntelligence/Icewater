
rule p3f7_5b9116c1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3f7.5b9116c1cc000b12"
     cluster="p3f7.5b9116c1cc000b12"
     cluster_size="5"
     filetype = "ASCII text"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="smsreg androidos riskware"
     md5_hashes="['0f881e9012c9603b3673c1a5a86ffcef','41893378143cc1f6c66870e0907915fc','d6e476f43c1589befd638e14c1d828c5']"

   strings:
      $hex_string = { 69bcc36575716ea0d7d2e4cae36f96fea219602eaca3e7be956133b41aae473706b92d64f89b5eb2e56ddf58aba55afb0e7f79155636268bb5fdbd80ec7c03ce }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
